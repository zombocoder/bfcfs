// SPDX-License-Identifier: GPL-2.0
/*
 * BFC Filesystem - Data verification and integrity checking
 * 
 * Copyright (c) 2021 zombocoder (Taras Havryliak)
 * Copyright (c) 2024 bfcfs contributors
 */

#include <linux/crc32c.h>

#include "bfcfs.h"

u32 bfcfs_crc32c(const void *data, size_t len)
{
	return crc32c(0, data, len);
}

int bfcfs_verify_chunk_crc(const void *data, size_t len, u32 expected)
{
	u32 calculated = bfcfs_crc32c(data, len);
	
	if (calculated != expected) {
		pr_debug("bfcfs: CRC mismatch - calculated: 0x%08x, expected: 0x%08x\n",
			 calculated, expected);
		return -EBADMSG;
	}
	
	return 0;
}