// SPDX-License-Identifier: GPL-2.0
/*
 * BFC Filesystem - Cryptographic operations (simplified for MVP)
 * 
 * Copyright (c) 2021 zombocoder (Taras Havryliak)
 * Copyright (c) 2024 bfcfs contributors
 */

#include "bfcfs.h"

int bfcfs_setup_crypto(struct bfcfs_sb *sbi)
{
	/* Check if container has encrypted files */
	if (sbi->features & BFC_FEATURE_AEAD) {
		bfcfs_warn(sbi->sb, "container has encrypted files, but encryption not supported in this build");
		bfcfs_warn(sbi->sb, "encrypted files will be inaccessible");
	}

	/* For MVP, we don't support encryption */
	sbi->has_key = false;
	sbi->aead = NULL;
	
	bfcfs_debug(sbi->sb, "crypto setup complete (encryption disabled)");
	return 0;
}

void bfcfs_cleanup_crypto(struct bfcfs_sb *sbi)
{
	/* Nothing to clean up in MVP version */
	sbi->has_key = false;
	sbi->aead = NULL;
}

int bfcfs_decrypt_chunk(struct bfcfs_sb *sbi, const struct bfcfs_ext *ext,
			u32 chunk_id, const void *ciphertext, u32 ciphertext_len,
			void *plaintext, u32 plaintext_len)
{
	/* Not implemented in MVP - return error */
	bfcfs_debug(sbi->sb, "decrypt_chunk: encryption not supported in MVP");
	return -EOPNOTSUPP;
}