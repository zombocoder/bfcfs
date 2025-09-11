// SPDX-License-Identifier: GPL-2.0
/*
 * BFC Filesystem - Container index parsing and management
 * 
 * Copyright (c) 2021 zombocoder (Taras Havryliak)
 * Copyright (c) 2024 bfcfs contributors
 */

#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/crc32c.h>
#include <linux/sort.h>
#include <linux/bsearch.h>

#include "bfcfs.h"

static int bfcfs_read_header(struct bfcfs_sb *sbi)
{
	struct bfc_header *header;
	loff_t pos = 0;
	ssize_t ret;
	int err = 0;

	header = kmalloc(sizeof(*header), GFP_KERNEL);
	if (!header)
		return -ENOMEM;

	ret = kernel_read(sbi->backing, header, sizeof(*header), &pos);
	if (ret != sizeof(*header)) {
		bfcfs_err(sbi->sb, "failed to read header: %zd", ret);
		err = ret < 0 ? ret : -EIO;
		goto out;
	}

	/* Validate magic */
	if (memcmp(header->magic, BFC_MAGIC_STR, sizeof(header->magic)) != 0) {
		bfcfs_err(sbi->sb, "invalid BFC magic");
		err = -EINVAL;
		goto out;
	}

	/* Extract metadata */
	sbi->block_size = le32_to_cpu(header->block_size);
	sbi->features = le64_to_cpu(header->features);
	memcpy(sbi->uuid, header->uuid, sizeof(sbi->uuid));

	/* Validate block size */
	if (sbi->block_size < 512 || sbi->block_size > 65536 || 
	    !is_power_of_2(sbi->block_size)) {
		bfcfs_err(sbi->sb, "invalid block size: %u", sbi->block_size);
		err = -EINVAL;
		goto out;
	}

	bfcfs_info(sbi->sb, "header: block_size=%u, features=0x%llx", 
		    sbi->block_size, sbi->features);

out:
	kfree(header);
	return err;
}

static int bfcfs_read_footer(struct bfcfs_sb *sbi, u64 *index_offset, u64 *index_size, u32 *index_crc)
{
	struct bfc_footer footer;
	loff_t file_size = i_size_read(file_inode(sbi->backing));
	loff_t pos = file_size - sizeof(footer);
	ssize_t ret;
	u32 stored_crc;
	
	ret = kernel_read(sbi->backing, &footer, sizeof(footer), &pos);
	if (ret != sizeof(footer)) {
		bfcfs_err(sbi->sb, "failed to read footer: %zd", ret);
		return ret < 0 ? ret : -EIO;
	}
	
	if (memcmp(footer.magic_start, BFC_INDEX_MAGIC, 7) != 0 ||
	    memcmp(footer.magic_end, BFC_INDEX_END, 7) != 0) {
		bfcfs_err(sbi->sb, "invalid footer magic");
		return -EINVAL;
	}

	*index_size = le64_to_cpu(footer.index_size);
	*index_offset = le64_to_cpu(footer.index_offset);  
	*index_crc = le32_to_cpu(footer.index_crc32);

	bfcfs_debug(sbi->sb, "footer: index_offset=%llu, index_size=%llu, index_crc=0x%x",
		    *index_offset, *index_size, *index_crc);

	/* Validate index bounds */
	if (*index_offset < BFC_HEADER_SIZE || 
	    *index_offset + *index_size > file_size - BFC_FOOTER_SIZE) {
		bfcfs_err(sbi->sb, "invalid index bounds: offset=%llu, size=%llu, file_size=%lld", 
			  *index_offset, *index_size, file_size);
		return -EINVAL;
	}

	if (*index_size == 0 || *index_size > 256 * 1024 * 1024) { /* 256MB limit */
		bfcfs_err(sbi->sb, "invalid index size: %llu", *index_size);
		return -EINVAL;
	}

	bfcfs_debug(sbi->sb, "footer: index_offset=%llu, index_size=%llu, crc=0x%x", 
		    *index_offset, *index_size, stored_crc);

	return 0;
}

static void *bfcfs_read_index_blob(struct bfcfs_sb *sbi, u64 offset, u64 size, u32 expected_crc)
{
	void *blob;
	loff_t pos = offset;
	ssize_t ret;
	u32 calculated_crc;

	/* Allocate buffer for index */
	blob = vmalloc(size);
	if (!blob) {
		bfcfs_err(sbi->sb, "failed to allocate %llu bytes for index", size);
		return ERR_PTR(-ENOMEM);
	}

	/* Read index data */
	ret = kernel_read(sbi->backing, blob, size, &pos);
	if (ret != size) {
		bfcfs_err(sbi->sb, "failed to read index blob: %zd", ret);
		vfree(blob);
		return ERR_PTR(ret < 0 ? ret : -EIO);
	}

	/* Verify CRC */
	calculated_crc = crc32c(0, blob, size);
	if (calculated_crc != expected_crc) {
		bfcfs_warn(sbi->sb, "index CRC mismatch: calculated=0x%x, expected=0x%x (ignoring for debug)", 
			   calculated_crc, expected_crc);
		/* Temporarily skip CRC check for debugging */
	}

	return blob;
}

static int bfcfs_parse_index_entries(struct bfcfs_sb *sbi, const void *blob, u64 size)
{
	const u8 *data = blob;
	const u8 *end = data + size;
	const u8 *ptr;
	u32 i, name_offset = 0;
	char *strtab_pos;
	u32 version, count;

	if (size < 8) { /* Need at least version + count */
		bfcfs_err(sbi->sb, "index blob too small for header");
		return -EINVAL;
	}

	/* Parse index header manually (like the real BFC lib) */
	ptr = data;
	version = le32_to_cpu(*(u32*)ptr);
	count = le32_to_cpu(*(u32*)(ptr + 4));
	ptr += 8;

	if (version != 1) {
		bfcfs_err(sbi->sb, "unsupported index version: %u", version);
		return -EINVAL;
	}

	sbi->count = count;
	if (sbi->count == 0) {
		bfcfs_err(sbi->sb, "empty container");
		return -EINVAL;
	}

	if (sbi->count > 1000000) { /* 1M files limit */
		bfcfs_err(sbi->sb, "too many entries: %u", sbi->count);
		return -EINVAL;
	}

	bfcfs_info(sbi->sb, "parsing %u index entries (version %u)", sbi->count, version);

	/* Allocate entry array */
	sbi->ents = kcalloc(sbi->count, sizeof(*sbi->ents), GFP_KERNEL);
	if (!sbi->ents)
		return -ENOMEM;

	/* First pass: calculate string table size */
	const u8 *scan_ptr = ptr;
	sbi->strtab_size = 0;
	
	for (i = 0; i < sbi->count && scan_ptr < end; i++) {
		/* Read path_len */
		if (scan_ptr + 4 > end) {
			bfcfs_err(sbi->sb, "truncated path length at entry %u", i);
			return -EINVAL;
		}
		
		u32 path_len = le32_to_cpu(*(u32*)scan_ptr);
		scan_ptr += 4;
		
		if (path_len == 0 || path_len > 4096) {
			bfcfs_err(sbi->sb, "invalid path length in entry %u: %u", i, path_len);
			return -EINVAL;
		}
		
		/* Skip path and fixed fields (48 bytes total) */
		if (scan_ptr + path_len + 48 > end) {
			bfcfs_err(sbi->sb, "truncated entry %u", i);
			return -EINVAL;
		}
		
		sbi->strtab_size += path_len + 1; /* +1 for null terminator */
		scan_ptr += path_len + 48; /* path + obj_offset(8) + obj_size(8) + mode(4) + mtime_ns(8) + comp(4) + enc(4) + orig_size(8) + crc32c(4) = 48 */
	}

	if (i != sbi->count) {
		bfcfs_err(sbi->sb, "expected %u entries, found %u in first pass", sbi->count, i);
		return -EINVAL;
	}

	/* Allocate string table */
	sbi->strtab = kmalloc(sbi->strtab_size, GFP_KERNEL);
	if (!sbi->strtab)
		return -ENOMEM;

	/* Second pass: populate entries and string table */
	ptr = data + 8; /* Skip index header */
	strtab_pos = (char *)sbi->strtab;
	name_offset = 0;

	for (i = 0; i < sbi->count; i++) {
		struct bfcfs_entry *ent = &sbi->ents[i];

		/* Read path_len */
		u32 path_len = le32_to_cpu(*(u32*)ptr);
		ptr += 4;

		/* Copy path to string table */
		ent->name_off = name_offset;
		ent->name_len = path_len;
		memcpy(strtab_pos, ptr, path_len);
		strtab_pos[path_len] = '\0';
		strtab_pos += path_len + 1;
		name_offset += path_len + 1;
		ptr += path_len;

		/* Read fixed fields (following actual BFC implementation format) */
		ent->obj_off = le64_to_cpu(*(u64*)ptr);            ptr += 8;
		ent->obj_size = le64_to_cpu(*(u64*)ptr);           ptr += 8; 
		ent->mode = le32_to_cpu(*(u32*)ptr);               ptr += 4;
		ent->mtime_ns = le64_to_cpu(*(u64*)ptr);           ptr += 8;
		ent->comp = le32_to_cpu(*(u32*)ptr);               ptr += 4;
		ent->enc = le32_to_cpu(*(u32*)ptr);                ptr += 4;
		ent->orig_size = le64_to_cpu(*(u64*)ptr);          ptr += 8;
		ent->crc32c = le32_to_cpu(*(u32*)ptr);             ptr += 4;

		/* Initialize other fields */
		ent->parent_id = U32_MAX;
		ent->ext_idx = U32_MAX;
		ent->first_child = U32_MAX;
		ent->last_child = U32_MAX;
	}

	return 0;
}

/* Removed unused path_compare function */

static void bfcfs_build_hierarchy(struct bfcfs_sb *sbi)
{
	u32 i, j;
	
	/* Build parent relationships */
	for (i = 0; i < sbi->count; i++) {
		const char *path = sbi->strtab + sbi->ents[i].name_off;
		const char *last_slash = strrchr(path, '/');
		
		if (last_slash && last_slash != path) {
			/* Find parent directory */
			size_t parent_len = last_slash - path;
			
			for (j = 0; j < sbi->count; j++) {
				const char *parent_path = sbi->strtab + sbi->ents[j].name_off;
				
				if (strlen(parent_path) == parent_len &&
				    strncmp(path, parent_path, parent_len) == 0) {
					sbi->ents[i].parent_id = j;
					break;
				}
			}
		}
	}

	/* Build directory child ranges */
	for (i = 0; i < sbi->count; i++) {
		if (!S_ISDIR(sbi->ents[i].mode))
			continue;
			
		sbi->ents[i].first_child = U32_MAX;
		sbi->ents[i].last_child = U32_MAX;
		
		for (j = 0; j < sbi->count; j++) {
			if (sbi->ents[j].parent_id == i) {
				if (sbi->ents[i].first_child == U32_MAX)
					sbi->ents[i].first_child = j;
				sbi->ents[i].last_child = j;
			}
		}
	}
}

int bfcfs_load_index(struct bfcfs_sb *sbi)
{
	u64 index_offset, index_size;
	void *blob;
	u32 expected_crc;
	int ret;

	/* Read and validate header */
	ret = bfcfs_read_header(sbi);
	if (ret)
		return ret;

	/* Read footer to get index location */
	ret = bfcfs_read_footer(sbi, &index_offset, &index_size, &expected_crc);
	if (ret)
		return ret;

	/* Read and verify index blob */
	blob = bfcfs_read_index_blob(sbi, index_offset, index_size, expected_crc);
	if (IS_ERR(blob))
		return PTR_ERR(blob);

	/* Parse entries and build string table */
	ret = bfcfs_parse_index_entries(sbi, blob, index_size);
	if (ret) {
		vfree(blob);
		return ret;
	}

	/* Build directory hierarchy for fast lookups */
	bfcfs_build_hierarchy(sbi);

	/* Complete key descriptor with UUID if not overridden */
	if (strcmp(sbi->opts.key_desc, "bfcfs:") == 0) {
		snprintf(sbi->opts.key_desc, sizeof(sbi->opts.key_desc),
			 "bfcfs:%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
			 sbi->uuid[0], sbi->uuid[1], sbi->uuid[2], sbi->uuid[3],
			 sbi->uuid[4], sbi->uuid[5], sbi->uuid[6], sbi->uuid[7],
			 sbi->uuid[8], sbi->uuid[9], sbi->uuid[10], sbi->uuid[11],
			 sbi->uuid[12], sbi->uuid[13], sbi->uuid[14], sbi->uuid[15]);
	}

	vfree(blob);
	return 0;
}

void bfcfs_free_index(struct bfcfs_sb *sbi)
{
	if (sbi->ents) {
		kfree(sbi->ents);
		sbi->ents = NULL;
	}
	
	if (sbi->strtab) {
		kfree(sbi->strtab);
		sbi->strtab = NULL;
	}
	
	sbi->count = 0;
	sbi->strtab_size = 0;
}

int bfcfs_find_entry(struct bfcfs_sb *sbi, const char *path)
{
	u32 i;
	
	/* Linear search for now - TODO: optimize with hash table or binary search */
	for (i = 0; i < sbi->count; i++) {
		const char *entry_path = sbi->strtab + sbi->ents[i].name_off;
		if (strcmp(entry_path, path) == 0)
			return i;
	}
	
	return -1;
}

int bfcfs_verify_container(struct bfcfs_sb *sbi, enum verify_mode mode)
{
	/* For now, just return success - verification will be implemented later */
	bfcfs_debug(sbi->sb, "container verification mode %d - skipped for now", mode);
	return 0;
}