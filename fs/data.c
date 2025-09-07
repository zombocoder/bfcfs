// SPDX-License-Identifier: GPL-2.0
/*
 * BFC Filesystem - Data operations and page cache integration
 * 
 * Copyright (c) 2021 zombocoder (Taras Havryliak)
 * Copyright (c) 2024 bfcfs contributors
 */

#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/highmem.h>

#include "bfcfs.h"

static int bfcfs_readpage_plain(struct bfcfs_sb *sbi, struct bfcfs_entry *entry,
				struct page *page)
{
	loff_t file_offset = entry->obj_off + sizeof(struct bfc_obj_header) + 
			     entry->name_len + 
			     ((16 - ((sizeof(struct bfc_obj_header) + entry->name_len) % 16)) % 16);
	loff_t page_offset = page->index << PAGE_SHIFT;
	loff_t read_offset = file_offset + page_offset;
	size_t to_read = min_t(size_t, PAGE_SIZE, entry->orig_size - page_offset);
	void *page_addr;
	ssize_t ret;

	if (page_offset >= entry->orig_size) {
		/* Beyond file size */
		zero_user_segment(page, 0, PAGE_SIZE);
		SetPageUptodate(page);
		unlock_page(page);
		return 0;
	}

	page_addr = kmap(page);
	if (!page_addr) {
		unlock_page(page);
		return -ENOMEM;
	}

	/* Clear page first */
	memset(page_addr, 0, PAGE_SIZE);

	/* Read data from container file */
	ret = kernel_read(sbi->backing, page_addr, to_read, &read_offset);
	
	kunmap(page);

	if (ret < 0) {
		bfcfs_err(sbi->sb, "failed to read page: %zd", ret);
		unlock_page(page);
		return ret;
	}

	if (ret != to_read) {
		bfcfs_warn(sbi->sb, "short read: expected %zu, got %zd", to_read, ret);
	}

	SetPageUptodate(page);
	unlock_page(page);
	return 0;
}

static int bfcfs_read_folio(struct file *file, struct folio *folio)
{
	struct page *page = &folio->page;
	struct inode *inode = file ? file_inode(file) : page->mapping->host;
	struct super_block *sb = inode->i_sb;
	struct bfcfs_sb *sbi = BFCFS_SB(sb);
	struct bfcfs_inode *bi = BFCFS_I(inode);
	struct bfcfs_entry *entry = &sbi->ents[bi->entry_id];

	bfcfs_debug(sb, "read_folio: entry_id=%u, page=%lu", bi->entry_id, page->index);

	/* For now, only handle uncompressed, unencrypted files */
	if (entry->comp != BFC_COMP_NONE || entry->enc != BFC_ENC_NONE) {
		bfcfs_debug(sb, "compressed/encrypted files not yet supported");
		zero_user_segment(page, 0, PAGE_SIZE);
		SetPageError(page);
		unlock_page(page);
		return -EOPNOTSUPP;
	}

	return bfcfs_readpage_plain(sbi, entry, page);
}

/* Legacy readpage wrapper for compatibility */
int bfcfs_readpage(struct file *file, struct page *page)
{
	struct folio *folio = page_folio(page);
	return bfcfs_read_folio(file, folio);
}

void bfcfs_readahead(struct readahead_control *rac)
{
	struct page *page;

	/* Simple readahead - just call readpage for each page */
	while ((page = readahead_page(rac))) {
		int ret = bfcfs_readpage(NULL, page);
		if (ret) {
			SetPageError(page);
			unlock_page(page);
		}
		put_page(page);
	}
}

const struct address_space_operations bfcfs_aops = {
	.read_folio	= bfcfs_read_folio,
	.readahead	= bfcfs_readahead,
};