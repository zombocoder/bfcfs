/* SPDX-License-Identifier: Apache-2.0 */
/*
 * BFC Filesystem - Core definitions and data structures
 * 
 * Copyright (c) 2021 zombocoder (Taras Havryliak)
 * Copyright (c) 2024 bfcfs contributors
 */

#ifndef _BFCFS_H
#define _BFCFS_H

#include <linux/fs.h>
#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/crypto.h>
#include <linux/file.h>
#include <linux/path.h>
#include <linux/mempool.h>

/* BFC Format Constants */
#define BFCFS_MAGIC		0xBFCF5001
#define BFC_HEADER_SIZE		4096
#define BFC_FOOTER_SIZE		56
#define BFC_MAGIC_STR		"BFCFv1\0"
#define BFC_INDEX_MAGIC		"BFCFIDX"
#define BFC_INDEX_END		"BFCFEND"
#define BFC_EXT_MAGIC		0x58434642	/* "BFCX" */

/* BFC Feature Flags */
#define BFC_FEATURE_ZSTD	(1ULL << 0)	/* ZSTD compression */
#define BFC_FEATURE_AEAD	(1ULL << 1)	/* AEAD encryption */

/* Compression Types */
#define BFC_COMP_NONE		0
#define BFC_COMP_ZSTD		1

/* Encryption Types */
#define BFC_ENC_NONE		0
#define BFC_ENC_CHACHA20_POLY1305	1

/* Error Codes (from BFC API) */
#define BFC_OK			0
#define BFC_E_BADMAGIC		-1
#define BFC_E_IO		-2
#define BFC_E_CRC		-3
#define BFC_E_INVAL		-4
#define BFC_E_EXISTS		-5
#define BFC_E_NOTFOUND		-6
#define BFC_E_PERM		-7

/* Mount Options */
enum verify_mode {
	VERIFY_NONE = 0,
	VERIFY_SHALLOW = 1,
	VERIFY_DEEP = 2
};

struct bfcfs_mount_opts {
	char source[PATH_MAX];		/* Path to .bfc file */
	char key_desc[128];		/* Keyring descriptor */
	enum verify_mode verify;	/* Verification level */
	bool noreadahead;		/* Disable readahead */
};

/* On-disk BFC structures */

struct bfc_header {
	char magic[8];			/* "BFCFv1\0" */
	u32 header_crc32;		/* CRC32 of remaining header bytes */
	u32 block_size;			/* alignment boundary (default 4096) */
	u64 features;			/* feature flags */
	u8 uuid[16];			/* RFC 4122 v4 UUID */
	u8 enc_salt[32];		/* salt for key derivation */
	u8 reserved[4024];		/* zero-filled */
} __packed;

struct bfc_footer {
	char magic_start[8];		/* "BFCFIDX" */
	u64 index_size;			/* Size comes FIRST in real format */
	u32 index_crc32;		/* CRC32, not CRC32C */
	u64 index_offset;		/* Offset comes AFTER size */
	u32 container_crc;		/* Additional field */
	u8 reserved[16];		/* 16 bytes reserved */
	char magic_end[8];		/* "BFCFEND" */
} __packed;

struct bfc_obj_header {
	u32 type;
	u32 name_len;
	u64 content_size;
	u32 mode;
	u64 mtime_ns;
	u32 comp;
	u32 enc;
	u32 crc32c;
	u32 reserved;
} __packed;

struct bfc_index_header {
	u32 version;
	u32 count;
	u32 reserved[2];
} __packed;

struct bfc_index_entry {
	u64 obj_offset;
	u64 obj_size;
	u64 content_size;
	u32 mode;
	u64 mtime_ns;
	u32 comp;
	u32 enc;
	u32 crc32c;
	u32 name_len;
	/* Variable-length name follows */
} __packed;

/* Index extensions for chunked compression/encryption */
struct bfc_index_ext_header {
	u32 magic;			/* "BFCX" */
	u16 version;
	u16 reserved;
	u32 count;
} __packed;

struct bfc_index_ext {
	u32 entry_id;
	u8 flags;
	u8 comp;
	u8 enc;
	u8 chunk_log2;			/* Chunk size = 1 << chunk_log2 */
	u32 chunk_count;
	u64 chunk_tbl_off;		/* Offset to chunk table */
	u8 file_nonce[12];		/* Base nonce for encryption */
	u8 pad[4];
} __packed;

struct bfc_chunk_desc {
	u64 phys_off;			/* Physical offset in container */
	u32 phys_len;			/* Physical length (compressed+encrypted) */
	u32 crc32c;			/* CRC of uncompressed data */
} __packed;

/* In-kernel data structures */

struct bfcfs_entry {
	u32 mode;			/* POSIX permissions */
	u64 mtime_ns;			/* Modification time */
	u64 orig_size;			/* Uncompressed file size */
	u32 comp;			/* Compression type */
	u32 enc;			/* Encryption type */
	u32 crc32c;			/* CRC32C checksum */
	u64 obj_off;			/* Object offset in container */
	u64 obj_size;			/* Object size in container */
	
	/* Indexing fields for kernel use */
	u32 name_off;			/* Offset in string table */
	u16 name_len;			/* Length of name */
	u32 parent_id;			/* Parent directory entry ID */
	u32 ext_idx;			/* Index into ext[] or U32_MAX */
	
	/* Directory optimization */
	u32 first_child;		/* First child entry index */
	u32 last_child;			/* Last child entry index */
};

struct bfcfs_ext {
	u8 flags;
	u8 comp;
	u8 enc;
	u8 chunk_log2;			/* log2(chunk_size) */
	u32 chunk_cnt;
	u64 chunk_tbl_off;		/* Offset to chunk table */
	u8 file_nonce[12];		/* Base nonce for AEAD */
	
	/* Cached chunk descriptors (loaded on demand) */
	struct bfc_chunk_desc *chunks;
	struct mutex chunk_lock;
};

/* Superblock private data */
struct bfcfs_sb {
	struct super_block *sb;
	struct file *backing;		/* Opened .bfc file */
	
	/* Container metadata */
	u8 uuid[16];
	u32 block_size;
	u64 features;
	
	/* Index data (loaded into memory) */
	struct bfcfs_entry *ents;	/* entries[count] */
	u32 count;			/* Number of entries */
	const char *strtab;		/* String table for paths */
	u32 strtab_size;
	
	/* Extensions for compression/encryption */
	struct bfcfs_ext *ext;		/* ext[ext_count] or NULL */
	u32 ext_count;
	
	/* Directory hierarchy optimization */
	u32 *dir_first_child;		/* maps entry id -> first child idx */
	u32 *dir_last_child;		/* maps entry id -> last child idx */
	
	/* Mount options */
	struct bfcfs_mount_opts opts;
	
	/* Crypto context */
	struct crypto_aead *aead;	/* ChaCha20-Poly1305 context */
	u8 aead_key[32];		/* AEAD key */
	bool has_key;			/* Key loaded from keyring */
	
	/* Performance optimization */
	bool noreadahead;
	enum verify_mode verify;
	
	/* Memory pools for decompression */
	mempool_t *decomp_pool;		/* Scratch buffers */
	struct mutex crypto_lock;	/* Protects crypto operations */
};

/* Inode private data */
struct bfcfs_inode {
	u32 entry_id;			/* Index into sbi->ents[] */
	struct inode inode;
};

static inline struct bfcfs_sb *BFCFS_SB(struct super_block *sb)
{
	return sb->s_fs_info;
}

static inline struct bfcfs_inode *BFCFS_I(struct inode *inode)
{
	return container_of(inode, struct bfcfs_inode, inode);
}

/* Function declarations */

/* super.c */
int bfcfs_fill_super(struct super_block *sb, void *data, int silent);
void bfcfs_kill_sb(struct super_block *sb);

/* opts.c */
int bfcfs_parse_mount_options(char *data, struct bfcfs_mount_opts *opts);

/* index.c */
int bfcfs_load_index(struct bfcfs_sb *sbi);
void bfcfs_free_index(struct bfcfs_sb *sbi);
int bfcfs_find_entry(struct bfcfs_sb *sbi, const char *path);
int bfcfs_verify_container(struct bfcfs_sb *sbi, enum verify_mode mode);

/* inode.c */
struct inode *bfcfs_make_root_inode(struct super_block *sb);
struct inode *bfcfs_iget(struct super_block *sb, u32 entry_id);
int bfcfs_readdir(struct file *file, struct dir_context *ctx);
struct dentry *bfcfs_lookup(struct inode *dir, struct dentry *dentry,
			    unsigned int flags);

/* data.c */
int bfcfs_readpage(struct file *file, struct page *page);
void bfcfs_readahead(struct readahead_control *rac);

/* crypto.c */
int bfcfs_setup_crypto(struct bfcfs_sb *sbi);
void bfcfs_cleanup_crypto(struct bfcfs_sb *sbi);
int bfcfs_decrypt_chunk(struct bfcfs_sb *sbi, const struct bfcfs_ext *ext,
			u32 chunk_id, const void *ciphertext, u32 ciphertext_len,
			void *plaintext, u32 plaintext_len);

/* verify.c */
u32 bfcfs_crc32c(const void *data, size_t len);
int bfcfs_verify_chunk_crc(const void *data, size_t len, u32 expected);

/* Utility macros */
#define bfcfs_err(sb, fmt, ...) \
	pr_err("bfcfs (%s): " fmt "\n", sb->s_id, ##__VA_ARGS__)

#define bfcfs_warn(sb, fmt, ...) \
	pr_warn("bfcfs (%s): " fmt "\n", sb->s_id, ##__VA_ARGS__)

#define bfcfs_info(sb, fmt, ...) \
	pr_info("bfcfs (%s): " fmt "\n", sb->s_id, ##__VA_ARGS__)

#define bfcfs_debug(sb, fmt, ...) \
	pr_debug("bfcfs (%s): " fmt "\n", sb->s_id, ##__VA_ARGS__)

#endif /* _BFCFS_H */