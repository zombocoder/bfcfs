// SPDX-License-Identifier: GPL-2.0
/*
 * BFC Filesystem - Superblock operations and module management
 * 
 * Copyright (c) 2021 zombocoder (Taras Havryliak)
 * Copyright (c) 2024 bfcfs contributors
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/slab.h>
#include <linux/statfs.h>
#include <linux/file.h>
#include <linux/pagemap.h>
#include <linux/namei.h>
#include <linux/crc32c.h>

#include "bfcfs.h"

MODULE_AUTHOR("zombocoder (Taras Havryliak)");
MODULE_DESCRIPTION("BFC read-only filesystem");
MODULE_LICENSE("GPL v2");
MODULE_VERSION("0.1.0");

/* Use VFS inode allocation - no custom allocator needed */

static void bfcfs_evict_inode(struct inode *inode)
{
	truncate_inode_pages_final(&inode->i_data);
	clear_inode(inode);
}

static void bfcfs_put_super(struct super_block *sb)
{
	struct bfcfs_sb *sbi = BFCFS_SB(sb);

	if (!sbi)
		return;

	bfcfs_info(sb, "unmounting filesystem");
	
	/* Mark backing file as NULL first to prevent new I/O */
	if (sbi->backing) {
		struct file *backing = sbi->backing;
		sbi->backing = NULL;
		filp_close(backing, NULL);
	}
	
	/* Clean up in reverse order of initialization */
	bfcfs_cleanup_crypto(sbi);
	bfcfs_free_index(sbi);
	
	/* Ensure all pending operations complete before freeing */
	synchronize_rcu();
	
	/* Clear superblock info before freeing - log BEFORE clearing */
	bfcfs_info(sb, "filesystem unmounted cleanly");
	sb->s_fs_info = NULL;
	kfree(sbi);
}

static int bfcfs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct super_block *sb = dentry->d_sb;
	struct bfcfs_sb *sbi = BFCFS_SB(sb);
	struct bfcfs_entry *ents;
	u64 total_size = 0;
	u32 i, count;

	/* Add safety check */
	if (!sbi) {
		bfcfs_err(sb, "statfs called with NULL sbi");
		return -EIO;
	}
	
	/* Get stable references to avoid races during unmount */
	ents = sbi->ents;
	count = sbi->count;
	
	if (!ents) {
		/* Filesystem is being unmounted */
		return -EIO;
	}

	/* Calculate total uncompressed size */
	for (i = 0; i < count; i++) {
		if (S_ISREG(ents[i].mode))
			total_size += ents[i].orig_size;
	}

	buf->f_type = BFCFS_MAGIC;
	buf->f_bsize = sbi->block_size;
	buf->f_blocks = total_size >> ilog2(sbi->block_size);
	buf->f_bfree = 0;	/* Read-only filesystem */
	buf->f_bavail = 0;
	buf->f_files = count;
	buf->f_ffree = 0;
	buf->f_fsid.val[0] = (u32)(sbi->uuid[0] ^ sbi->uuid[4] ^ 
				   sbi->uuid[8] ^ sbi->uuid[12]);
	buf->f_fsid.val[1] = (u32)(sbi->uuid[1] ^ sbi->uuid[5] ^ 
				   sbi->uuid[9] ^ sbi->uuid[13]);
	buf->f_namelen = 255;	/* Standard filename length limit */
	buf->f_frsize = sbi->block_size;
	buf->f_flags = ST_RDONLY;

	return 0;
}

static int bfcfs_sync_fs(struct super_block *sb, int wait)
{
	/* Read-only filesystem - nothing to sync */
	return 0;
}

static const struct super_operations bfcfs_sops = {
	.evict_inode	= bfcfs_evict_inode,
	.put_super	= bfcfs_put_super,
	.sync_fs	= bfcfs_sync_fs,
	.statfs		= bfcfs_statfs,
	.drop_inode	= generic_delete_inode,
};

static int bfcfs_validate_backing_file(struct file *file)
{
	struct inode *inode = file_inode(file);
	
	/* Must be a regular file */
	if (!S_ISREG(inode->i_mode)) {
		pr_err("bfcfs: backing file is not a regular file\n");
		return -EINVAL;
	}
	
	/* Must be readable */
	if (!(file->f_mode & FMODE_READ)) {
		pr_err("bfcfs: backing file is not readable\n");
		return -EACCES;
	}
	
	/* Must have some minimum size */
	if (inode->i_size < BFC_HEADER_SIZE + BFC_FOOTER_SIZE) {
		pr_err("bfcfs: backing file too small (%lld bytes)\n", inode->i_size);
		return -EINVAL;
	}
	
	return 0;
}

int bfcfs_fill_super(struct super_block *sb, void *data, int silent)
{
	struct bfcfs_sb *sbi;
	struct inode *root_inode;
	int ret;

	/* Allocate superblock private data */
	sbi = kzalloc(sizeof(*sbi), GFP_KERNEL);
	if (!sbi)
		return -ENOMEM;

	sbi->sb = sb;
	sb->s_fs_info = sbi;
	sb->s_magic = BFCFS_MAGIC;
	sb->s_op = &bfcfs_sops;
	sb->s_flags |= SB_RDONLY;	/* Always read-only */
	sb->s_maxbytes = MAX_LFS_FILESIZE;
	
	/* Initialize locks */
	mutex_init(&sbi->crypto_lock);

	/* Parse mount options */
	ret = bfcfs_parse_mount_options(data, &sbi->opts);
	if (ret) {
		if (!silent)
			bfcfs_err(sb, "invalid mount options");
		goto out_free_sbi;
	}

	/* Open backing file */
	sbi->backing = filp_open(sbi->opts.source, O_RDONLY | O_LARGEFILE, 0);
	if (IS_ERR(sbi->backing)) {
		ret = PTR_ERR(sbi->backing);
		if (!silent)
			bfcfs_err(sb, "cannot open backing file '%s': %d", 
				  sbi->opts.source, ret);
		goto out_free_sbi;
	}

	/* Validate backing file */
	ret = bfcfs_validate_backing_file(sbi->backing);
	if (ret)
		goto out_close_file;

	/* Load and parse the container index */
	ret = bfcfs_load_index(sbi);
	if (ret) {
		if (!silent)
			bfcfs_err(sb, "failed to load container index: %d", ret);
		goto out_close_file;
	}

	bfcfs_info(sb, "loaded container with %u entries", sbi->count);

	/* Set up crypto if needed */
	if (sbi->features & BFC_FEATURE_AEAD) {
		ret = bfcfs_setup_crypto(sbi);
		if (ret && ret != -ENOKEY) {
			if (!silent)
				bfcfs_err(sb, "failed to setup crypto: %d", ret);
			goto out_free_index;
		}
		if (ret == -ENOKEY)
			bfcfs_warn(sb, "no encryption key found, encrypted files will be inaccessible");
	}

	/* Verify container integrity if requested */
	if (sbi->opts.verify != VERIFY_NONE) {
		ret = bfcfs_verify_container(sbi, sbi->opts.verify);
		if (ret) {
			if (!silent)
				bfcfs_err(sb, "container verification failed: %d", ret);
			goto out_cleanup_crypto;
		}
		bfcfs_info(sb, "container verification passed");
	}

	/* Set logical block size for VFS layer (file-based, not block device) */
	sb->s_blocksize = sbi->block_size;
	sb->s_blocksize_bits = ilog2(sbi->block_size);

	/* Create root inode */
	root_inode = bfcfs_make_root_inode(sb);
	if (IS_ERR(root_inode)) {
		ret = PTR_ERR(root_inode);
		if (!silent)
			bfcfs_err(sb, "failed to create root inode: %d", ret);
		goto out_cleanup_crypto;
	}

	/* Create root dentry */
	sb->s_root = d_make_root(root_inode);
	if (!sb->s_root) {
		ret = -ENOMEM;
		if (!silent)
			bfcfs_err(sb, "failed to create root dentry");
		goto out_cleanup_crypto;
	}

	bfcfs_info(sb, "mounted successfully (%s)", sbi->opts.source);
	return 0;

out_cleanup_crypto:
	bfcfs_cleanup_crypto(sbi);
out_free_index:
	bfcfs_free_index(sbi);
out_close_file:
	filp_close(sbi->backing, NULL);
out_free_sbi:
	sb->s_fs_info = NULL;
	kfree(sbi);
	return ret;
}

void bfcfs_kill_sb(struct super_block *sb)
{
	/* Let VFS handle cleanup through put_super() */
	kill_anon_super(sb);
}

static struct dentry *bfcfs_mount(struct file_system_type *fs_type,
				  int flags, const char *dev_name, void *data)
{
	return mount_nodev(fs_type, flags, data, bfcfs_fill_super);
}

static struct file_system_type bfcfs_type = {
	.owner		= THIS_MODULE,
	.name		= "bfcfs",
	.mount		= bfcfs_mount,
	.kill_sb	= bfcfs_kill_sb,
	.fs_flags	= 0,
};


static int __init bfcfs_init(void)
{
	int ret;

	pr_info("bfcfs: BFC filesystem module loading\n");


	/* Register filesystem */
	ret = register_filesystem(&bfcfs_type);
	if (ret) {
		pr_err("bfcfs: failed to register filesystem: %d\n", ret);
		return ret;
	}

	pr_info("bfcfs: filesystem registered successfully\n");
	return 0;
}

static void __exit bfcfs_exit(void)
{
	pr_info("bfcfs: unloading filesystem module\n");
	
	unregister_filesystem(&bfcfs_type);
	
	pr_info("bfcfs: filesystem unloaded\n");
}

module_init(bfcfs_init);
module_exit(bfcfs_exit);