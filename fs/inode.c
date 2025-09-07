// SPDX-License-Identifier: GPL-2.0
/*
 * BFC Filesystem - Inode operations
 * 
 * Copyright (c) 2021 zombocoder (Taras Havryliak)
 * Copyright (c) 2024 bfcfs contributors
 */

#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/slab.h>

#include "bfcfs.h"

static const struct inode_operations bfcfs_dir_inode_ops;
static const struct file_operations bfcfs_dir_file_ops;
static const struct inode_operations bfcfs_file_inode_ops;
static const struct file_operations bfcfs_file_file_ops;
static const struct address_space_operations bfcfs_aops;

struct inode *bfcfs_make_root_inode(struct super_block *sb)
{
	struct bfcfs_sb *sbi = BFCFS_SB(sb);
	struct inode *inode;
	int root_id;

	/* Find root directory entry (should be first, with path "/") */
	root_id = bfcfs_find_entry(sbi, "/");
	if (root_id < 0) {
		bfcfs_err(sb, "root directory not found in container");
		return ERR_PTR(-ENOENT);
	}

	if (!S_ISDIR(sbi->ents[root_id].mode)) {
		bfcfs_err(sb, "root entry is not a directory");
		return ERR_PTR(-ENOTDIR);
	}

	inode = bfcfs_iget(sb, root_id);
	if (IS_ERR(inode))
		return inode;

	return inode;
}

struct inode *bfcfs_iget(struct super_block *sb, u32 entry_id)
{
	struct bfcfs_sb *sbi = BFCFS_SB(sb);
	struct bfcfs_entry *entry;
	struct bfcfs_inode *bi;
	struct inode *inode;
	ino_t ino;

	if (entry_id >= sbi->count) {
		bfcfs_err(sb, "invalid entry ID: %u", entry_id);
		return ERR_PTR(-EINVAL);
	}

	entry = &sbi->ents[entry_id];

	/* Generate inode number from path hash and offset */
	ino = hash_64(entry->obj_off, 32) | ((u64)entry_id << 32);

	inode = iget_locked(sb, ino);
	if (!inode)
		return ERR_PTR(-ENOMEM);

	if (!(inode->i_state & I_NEW))
		return inode;

	bi = BFCFS_I(inode);
	bi->entry_id = entry_id;

	/* Set up inode attributes */
	inode->i_mode = entry->mode;
	inode->i_size = entry->orig_size;
	
	/* Set timestamps using modern kernel API */
	struct timespec64 ts = {
		.tv_sec = entry->mtime_ns / 1000000000ULL,
		.tv_nsec = entry->mtime_ns % 1000000000ULL
	};
	inode_set_mtime_to_ts(inode, ts);
	inode_set_atime_to_ts(inode, ts);
	inode_set_ctime_to_ts(inode, ts);
	inode->i_uid = GLOBAL_ROOT_UID;
	inode->i_gid = GLOBAL_ROOT_GID;

	if (S_ISDIR(inode->i_mode)) {
		inode->i_op = &bfcfs_dir_inode_ops;
		inode->i_fop = &bfcfs_dir_file_ops;
		/* Directory size is number of entries */
		inode->i_size = 0; /* Will be calculated in readdir */
	} else if (S_ISREG(inode->i_mode)) {
		inode->i_op = &bfcfs_file_inode_ops;
		inode->i_fop = &bfcfs_file_file_ops;
		inode->i_mapping->a_ops = &bfcfs_aops;
	} else {
		/* TODO: Support for symlinks and other file types */
		bfcfs_err(sb, "unsupported file type for entry %u", entry_id);
		iget_failed(inode);
		return ERR_PTR(-ENOTSUPP);
	}

	unlock_new_inode(inode);
	return inode;
}

int bfcfs_readdir(struct file *file, struct dir_context *ctx)
{
	struct inode *inode = file_inode(file);
	struct super_block *sb = inode->i_sb;
	struct bfcfs_sb *sbi = BFCFS_SB(sb);
	struct bfcfs_inode *bi = BFCFS_I(inode);
	struct bfcfs_entry *dir_entry = &sbi->ents[bi->entry_id];
	const char *dir_path = sbi->strtab + dir_entry->name_off;
	u32 i;
	int pos = 0;

	bfcfs_debug(sb, "readdir: %s, ctx->pos=%lld", dir_path, ctx->pos);

	if (ctx->pos == 0) {
		if (!dir_emit_dot(file, ctx))
			return 0;
		ctx->pos++;
		pos++;
	}

	if (ctx->pos == 1) {
		if (!dir_emit_dotdot(file, ctx))
			return 0;
		ctx->pos++;
		pos++;
	}

	/* Emit child entries */
	for (i = 0; i < sbi->count && pos < ctx->pos + 100; i++) {
		struct bfcfs_entry *entry = &sbi->ents[i];
		const char *entry_path = sbi->strtab + entry->name_off;
		const char *name;
		size_t name_len;

		/* Check if this entry is a direct child of current directory */
		if (entry->parent_id != bi->entry_id)
			continue;

		/* Extract filename from path */
		name = strrchr(entry_path, '/');
		if (name) {
			name++; /* Skip the '/' */
		} else {
			name = entry_path;
		}
		name_len = strlen(name);

		if (pos >= ctx->pos) {
			ino_t child_ino = hash_64(entry->obj_off, 32) | ((u64)i << 32);
			unsigned int d_type = S_ISDIR(entry->mode) ? DT_DIR : 
					      S_ISREG(entry->mode) ? DT_REG : DT_UNKNOWN;

			if (!dir_emit(ctx, name, name_len, child_ino, d_type))
				break;

			bfcfs_debug(sb, "  emitted: %s (ino=%lu, type=%u)", name, child_ino, d_type);
		}

		pos++;
	}

	ctx->pos = pos;
	return 0;
}

struct dentry *bfcfs_lookup(struct inode *dir, struct dentry *dentry,
			    unsigned int flags)
{
	struct super_block *sb = dir->i_sb;
	struct bfcfs_sb *sbi = BFCFS_SB(sb);
	struct bfcfs_inode *parent_bi = BFCFS_I(dir);
	struct bfcfs_entry *parent_entry = &sbi->ents[parent_bi->entry_id];
	const char *parent_path = sbi->strtab + parent_entry->name_off;
	char *full_path;
	int entry_id;
	struct inode *inode = NULL;

	/* Construct full path */
	if (strcmp(parent_path, "/") == 0) {
		full_path = kasprintf(GFP_KERNEL, "/%s", dentry->d_name.name);
	} else {
		full_path = kasprintf(GFP_KERNEL, "%s/%s", parent_path, dentry->d_name.name);
	}

	if (!full_path)
		return ERR_PTR(-ENOMEM);

	bfcfs_debug(sb, "lookup: %s", full_path);

	/* Find entry in container */
	entry_id = bfcfs_find_entry(sbi, full_path);
	if (entry_id >= 0) {
		inode = bfcfs_iget(sb, entry_id);
		if (IS_ERR(inode)) {
			kfree(full_path);
			return ERR_CAST(inode);
		}
	}

	kfree(full_path);
	return d_splice_alias(inode, dentry);
}

/* Inode operations */
static const struct inode_operations bfcfs_dir_inode_ops = {
	.lookup = bfcfs_lookup,
};

static const struct inode_operations bfcfs_file_inode_ops = {
};

/* File operations */
static const struct file_operations bfcfs_dir_file_ops = {
	.read		= generic_read_dir,
	.iterate_shared	= bfcfs_readdir,
	.llseek		= generic_file_llseek,
};

static const struct file_operations bfcfs_file_file_ops = {
	.read_iter	= generic_file_read_iter,
	.mmap		= generic_file_mmap,
	.llseek		= generic_file_llseek,
};

/* Address space operations - implemented in data.c */
extern const struct address_space_operations bfcfs_aops;