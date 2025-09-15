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
#include <linux/uio.h>

#include "bfcfs.h"

static const struct inode_operations bfcfs_dir_inode_ops;
static const struct file_operations bfcfs_dir_file_ops;
static const struct inode_operations bfcfs_file_inode_ops;
static const struct file_operations bfcfs_file_file_ops;
static const struct inode_operations bfcfs_symlink_inode_ops;

struct inode *bfcfs_make_root_inode(struct super_block *sb)
{
	struct bfcfs_sb *sbi = BFCFS_SB(sb);
	struct inode *inode;
	int root_id;

	/* Try to find explicit root directory entry with path "/" */
	root_id = bfcfs_find_entry(sbi, "/");
	if (root_id >= 0) {
		if (!S_ISDIR(sbi->ents[root_id].mode)) {
			bfcfs_err(sb, "root entry is not a directory");
			return ERR_PTR(-ENOTDIR);
		}
		inode = bfcfs_iget(sb, root_id);
		if (IS_ERR(inode))
			return inode;
		return inode;
	}

	/* No explicit root directory - create synthetic root inode */
	bfcfs_info(sb, "creating synthetic root directory");
	
	inode = new_inode(sb);
	if (!inode)
		return ERR_PTR(-ENOMEM);

	/* Store entry_id in i_private for synthetic root */
	inode->i_private = (void *)(long)-1;  /* Special marker for synthetic root */

	/* Set up synthetic root directory */
	inode->i_ino = 1;  /* Root inode number */
	inode->i_mode = S_IFDIR | 0755;
	inode->i_size = 0;
	inode->i_uid = GLOBAL_ROOT_UID;
	inode->i_gid = GLOBAL_ROOT_GID;
	
	/* Use current time for synthetic root */
	struct timespec64 now = current_time(inode);
	inode_set_mtime_to_ts(inode, now);
	inode_set_atime_to_ts(inode, now);
	inode_set_ctime_to_ts(inode, now);
	
	inode->i_op = &bfcfs_dir_inode_ops;
	inode->i_fop = &bfcfs_dir_file_ops;
	
	return inode;
}

struct inode *bfcfs_iget(struct super_block *sb, u32 entry_id)
{
	struct bfcfs_sb *sbi = BFCFS_SB(sb);
	struct bfcfs_entry *entry;
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

	/* Store entry_id in i_private */
	inode->i_private = (void *)(long)entry_id;

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
		/* No address space operations - use direct I/O */
	} else if (S_ISLNK(inode->i_mode)) {
		inode->i_op = &bfcfs_symlink_inode_ops;
		/* Symlink size is the length of the target path */
		/* i_size is already set to entry->orig_size which contains target length */
	} else {
		/* Other file types not supported yet */
		bfcfs_err(sb, "unsupported file type for entry %u", entry_id);
		iget_failed(inode);
		return ERR_PTR(-ENOTSUPP);
	}

	insert_inode_hash(inode);
	unlock_new_inode(inode);
	return inode;
}

int bfcfs_readdir(struct file *file, struct dir_context *ctx)
{
	struct inode *inode = file_inode(file);
	struct super_block *sb = inode->i_sb;
	struct bfcfs_sb *sbi = BFCFS_SB(sb);
	u32 entry_id = BFCFS_ENTRY_ID(inode);
	const char *dir_path;
	u32 i;
	int pos = 0;

	/* Handle synthetic root directory */
	if (entry_id == (u32)-1) {
		dir_path = "/";  /* Synthetic root path */
	} else {
		struct bfcfs_entry *dir_entry = &sbi->ents[entry_id];
		dir_path = sbi->strtab + dir_entry->name_off;
	}

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
		if (entry_id == (u32)-1) {
			/* For synthetic root, show top-level entries (no slash in path) */
			if (strchr(entry_path, '/') != NULL)
				continue;
		} else {
			/* For normal directories, use parent_id */
			if (entry->parent_id != entry_id)
				continue;
		}

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
					      S_ISREG(entry->mode) ? DT_REG :
					      S_ISLNK(entry->mode) ? DT_LNK : DT_UNKNOWN;

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
	u32 parent_entry_id = BFCFS_ENTRY_ID(dir);
	char *full_path;
	int entry_id;
	struct inode *inode = NULL;

	/* Handle synthetic root directory (entry_id = -1) */
	if (parent_entry_id == (u32)-1) {
		/* This is synthetic root, construct path as /name */
		full_path = kasprintf(GFP_KERNEL, "%s", dentry->d_name.name);
	} else {
		/* Normal directory - get parent path from entry */
		struct bfcfs_entry *parent_entry = &sbi->ents[parent_entry_id];
		const char *parent_path = sbi->strtab + parent_entry->name_off;
		
		/* Construct full path */
		if (strcmp(parent_path, "/") == 0) {
			full_path = kasprintf(GFP_KERNEL, "/%s", dentry->d_name.name);
		} else {
			full_path = kasprintf(GFP_KERNEL, "%s/%s", parent_path, dentry->d_name.name);
		}
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

/* Simple direct read - bypasses page cache for cleaner unmount */
static ssize_t bfcfs_file_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file_inode(file);
	struct super_block *sb = inode->i_sb;
	struct bfcfs_sb *sbi = BFCFS_SB(sb);
	u32 entry_id = BFCFS_ENTRY_ID(inode);
	loff_t pos = iocb->ki_pos;
	size_t count = iov_iter_count(iter);
	struct bfcfs_entry *entry;
	ssize_t ret = 0;
	void *buf;

	if (!sbi || !sbi->backing) {
		return -EIO;
	}

	if (entry_id >= sbi->count) {
		return -EINVAL;
	}

	entry = &sbi->ents[entry_id];
	
	if (pos >= entry->orig_size) {
		return 0;
	}
	
	count = min_t(size_t, count, entry->orig_size - pos);
	if (count == 0) {
		return 0;
	}

	buf = kmalloc(count, GFP_KERNEL);
	if (!buf) {
		return -ENOMEM;
	}

	/* Calculate content offset like in data.c */
	struct bfc_obj_header obj_hdr;
	loff_t hdr_pos = entry->obj_off;
	ssize_t hdr_ret = kernel_read(sbi->backing, &obj_hdr, sizeof(obj_hdr), &hdr_pos);
	
	if (hdr_ret == sizeof(obj_hdr)) {
		size_t hdr_name_size = sizeof(struct bfc_obj_header) + le16_to_cpu(obj_hdr.name_len);
		size_t padding = ((hdr_name_size + 15) & ~15ULL) - hdr_name_size;
		loff_t content_start = entry->obj_off + hdr_name_size + padding;
		loff_t read_pos = content_start + pos;

		ret = kernel_read(sbi->backing, buf, count, &read_pos);
		if (ret > 0) {
			if (copy_to_iter(buf, ret, iter) != ret) {
				ret = -EFAULT;
			} else {
				iocb->ki_pos += ret;
			}
		}
	} else {
		ret = -EIO;
	}

	kfree(buf);
	return ret;
}

static const struct file_operations bfcfs_file_file_ops = {
	.read_iter	= bfcfs_file_read_iter,
	.llseek		= generic_file_llseek,
};

/* Symlink operations */
static const char *bfcfs_get_link(struct dentry *dentry, struct inode *inode,
				  struct delayed_call *done)
{
	struct super_block *sb = inode->i_sb;
	struct bfcfs_sb *sbi = BFCFS_SB(sb);
	u32 entry_id = BFCFS_ENTRY_ID(inode);
	struct bfcfs_entry *entry;
	char *link_target;
	ssize_t ret;

	if (!sbi || !sbi->backing) {
		return ERR_PTR(-EIO);
	}

	if (entry_id >= sbi->count) {
		return ERR_PTR(-EINVAL);
	}

	entry = &sbi->ents[entry_id];
	
	if (!S_ISLNK(entry->mode)) {
		return ERR_PTR(-EINVAL);
	}

	/* Allocate buffer for symlink target */
	link_target = kmalloc(entry->orig_size + 1, GFP_KERNEL);
	if (!link_target) {
		return ERR_PTR(-ENOMEM);
	}

	/* Read symlink target from container */
	struct bfc_obj_header obj_hdr;
	loff_t hdr_pos = entry->obj_off;
	ssize_t hdr_ret = kernel_read(sbi->backing, &obj_hdr, sizeof(obj_hdr), &hdr_pos);
	
	if (hdr_ret != sizeof(obj_hdr)) {
		kfree(link_target);
		return ERR_PTR(-EIO);
	}

	/* Calculate content offset */
	size_t hdr_name_size = sizeof(struct bfc_obj_header) + le16_to_cpu(obj_hdr.name_len);
	size_t padding = ((hdr_name_size + 15) & ~15ULL) - hdr_name_size;
	loff_t content_start = entry->obj_off + hdr_name_size + padding;
	loff_t read_pos = content_start;

	/* Read the symlink target */
	ret = kernel_read(sbi->backing, link_target, entry->orig_size, &read_pos);
	if (ret != entry->orig_size) {
		kfree(link_target);
		return ERR_PTR(-EIO);
	}

	/* Null-terminate the target string */
	link_target[entry->orig_size] = '\0';

	/* Set up delayed cleanup */
	set_delayed_call(done, kfree_link, link_target);
	
	return link_target;
}

static const struct inode_operations bfcfs_symlink_inode_ops = {
	.get_link = bfcfs_get_link,
};

/* Address space operations - implemented in data.c */