# BFC Library API Reference

## Overview

BFC (Binary File Container) is a high-performance, single-file container format for Linux filesystem implementation. This document provides a comprehensive API reference for implementing a Linux filesystem based on the BFC library.

**Project**: BFC - Binary File Container  
**License**: Apache License 2.0  
**Language**: C17  
**Version**: v1.1.0

## Core Concepts

### Container Format

- **Single-file storage**: All files and directories stored in one `.bfc` file
- **Append-only design**: Crash-safe writes with atomic commits
- **Fast random access**: O(log N) file lookup with sorted index at EOF
- **POSIX metadata preservation**: Full permissions, timestamps, file types
- **Cross-platform**: UTF-8 paths with normalization

### File Format Structure

```
[Header 4 KiB] → [Data Objects...] → [Index] → [Footer 56B]
```

- **Header**: Magic, version, features, UUID (first 4 KiB)
- **Data Objects**: Type-length-value encoding, 16-byte aligned
- **Index**: Sorted path entries for O(log N) lookup
- **Footer**: Index location and validation data (last 56 bytes)

---

## Data Types and Constants

### Core Types

```c
typedef struct bfc bfc_t;              // Opaque container handle

typedef struct {
    const char* path;                   // UTF-8 file path
    uint32_t mode;                      // POSIX permission bits
    uint64_t mtime_ns;                  // Modification time in nanoseconds
    uint32_t comp;                      // Compression type
    uint32_t enc;                       // Encryption type
    uint64_t size;                      // Uncompressed file size
    uint32_t crc32c;                    // CRC32C checksum
    uint64_t obj_offset;                // Object offset in container
    uint64_t obj_size;                  // Object size in container
} bfc_entry_t;
```

### Error Codes

```c
#define BFC_OK 0                        // Success

typedef enum {
    BFC_E_BADMAGIC = -1,                // Invalid magic/format
    BFC_E_IO = -2,                      // I/O error (errno preserved)
    BFC_E_CRC = -3,                     // CRC/checksum mismatch
    BFC_E_INVAL = -4,                   // Invalid parameter
    BFC_E_EXISTS = -5,                  // Entry already exists
    BFC_E_NOTFOUND = -6,                // Entry not found
    BFC_E_PERM = -7,                    // Permission denied
} bfc_err_t;
```

### Feature Flags

```c
// Compression types
#define BFC_COMP_NONE 0                 // No compression
#define BFC_COMP_ZSTD 1                 // ZSTD compression

// Encryption types
#define BFC_ENC_NONE 0                  // No encryption
#define BFC_ENC_CHACHA20_POLY1305 1     // ChaCha20-Poly1305 AEAD

// Container feature flags
#define BFC_FEATURE_ZSTD (1ULL << 0)    // ZSTD compression support
#define BFC_FEATURE_AEAD (1ULL << 1)    // AEAD encryption support
```

---

## Writer API (Container Creation)

### Container Management

```c
// Create new container
int bfc_create(const char* filename, uint32_t block_size, uint64_t features, bfc_t** out);

// Finalize container (writes index + footer, fsync)
int bfc_finish(bfc_t* w);

// Close container handle
void bfc_close(bfc_t* w);
```

### Adding Content

```c
// Add file from FILE* stream
int bfc_add_file(bfc_t* w, const char* container_path, FILE* src,
                 uint32_t mode, uint64_t mtime_ns, uint32_t* out_crc);

// Add directory entry
int bfc_add_dir(bfc_t* w, const char* container_dir, uint32_t mode, uint64_t mtime_ns);
```

### Compression Configuration

```c
// Set compression type and level
int bfc_set_compression(bfc_t* w, uint8_t comp_type, int level);

// Set minimum file size for compression
int bfc_set_compression_threshold(bfc_t* w, size_t min_bytes);

// Get current compression type
uint8_t bfc_get_compression(bfc_t* w);
```

### Encryption Configuration

```c
// Set encryption from password (uses Argon2id key derivation)
int bfc_set_encryption_password(bfc_t* w, const char* password, size_t password_len);

// Set encryption from 32-byte key
int bfc_set_encryption_key(bfc_t* w, const uint8_t key[32]);

// Clear encryption settings
int bfc_clear_encryption(bfc_t* w);

// Get current encryption type
uint8_t bfc_get_encryption(bfc_t* w);
```

---

## Reader API (Container Access)

### Container Management

```c
// Open container for reading
int bfc_open(const char* filename, bfc_t** out);

// Close reader handle
void bfc_close_read(bfc_t* r);
```

### File System Operations

```c
// Get file/directory information (similar to stat())
int bfc_stat(bfc_t* r, const char* container_path, bfc_entry_t* out);

// List entries with callback (similar to readdir())
typedef int (*bfc_list_cb)(const bfc_entry_t* entry, void* user_data);
int bfc_list(bfc_t* r, const char* prefix_dir, bfc_list_cb callback, void* user_data);

// Read file content with offset and length (similar to pread())
size_t bfc_read(bfc_t* r, const char* container_path, uint64_t offset,
                void* buffer, size_t length);
```

### Encryption Support (Reader)

```c
// Check if container has encrypted files
int bfc_has_encryption(bfc_t* r);

// Set decryption password for reader
int bfc_reader_set_encryption_password(bfc_t* r, const char* password, size_t password_len);

// Set decryption key for reader
int bfc_reader_set_encryption_key(bfc_t* r, const uint8_t key[32]);
```

---

## Utility Functions

### File Extraction

```c
// Extract file to file descriptor (validates CRC)
int bfc_extract_to_fd(bfc_t* r, const char* container_path, int out_fd);
```

### Container Verification

```c
// Verify container integrity
// deep=0: check structure and index only
// deep=1: read and verify all file contents
int bfc_verify(bfc_t* r, int deep);
```

---

## Linux Filesystem Integration Patterns

### Filesystem Context Structure

```c
typedef struct {
    bfc_t* container;                   // BFC container handle
    char* container_path;               // Path to .bfc file
    uint8_t encryption_key[32];         // Cached encryption key
    int has_key;                        // Key availability flag
    // Add filesystem-specific caching structures
    struct {
        char* path;                     // Cached path
        bfc_entry_t entry;             // Cached entry
        time_t cache_time;             // Cache timestamp
    } stat_cache[CACHE_SIZE];
} bfcfs_context_t;
```

### FUSE Integration Mapping

| FUSE Operation | BFC API Mapping             |
| -------------- | --------------------------- |
| `getattr()`    | `bfc_stat()`                |
| `readdir()`    | `bfc_list()`                |
| `read()`       | `bfc_read()`                |
| `open()`       | Container already open      |
| `access()`     | Check `bfc_entry_t.mode`    |
| `readlink()`   | Not supported (no symlinks) |

### Performance Optimization Strategies

1. **Index Caching**: Keep sorted index in memory after `bfc_open()`
2. **Path Normalization**: Cache normalized paths to avoid repeated calls
3. **Read-ahead**: Use larger buffer sizes for sequential access
4. **Entry Caching**: Cache frequently accessed `bfc_entry_t` structures
5. **Batch Operations**: Group multiple `bfc_list()` calls when possible

---

## Error Handling Patterns

### Standard Pattern

```c
int result = bfc_operation(params...);
if (result != BFC_OK) {
    // For BFC_E_IO, errno is preserved
    if (result == BFC_E_IO) {
        return -errno;  // Return negative errno for FUSE
    }
    // Map other BFC errors to appropriate errno values
    switch (result) {
        case BFC_E_NOTFOUND: return -ENOENT;
        case BFC_E_INVAL:    return -EINVAL;
        case BFC_E_PERM:     return -EACCES;
        case BFC_E_CRC:      return -EIO;
        case BFC_E_BADMAGIC: return -EINVAL;
        default:             return -EIO;
    }
}
```

### Filesystem Error Mapping

| BFC Error        | Linux errno | Description              |
| ---------------- | ----------- | ------------------------ |
| `BFC_E_NOTFOUND` | `ENOENT`    | File/directory not found |
| `BFC_E_INVAL`    | `EINVAL`    | Invalid parameter        |
| `BFC_E_PERM`     | `EACCES`    | Permission denied        |
| `BFC_E_IO`       | `errno`     | I/O error (preserved)    |
| `BFC_E_CRC`      | `EIO`       | Data corruption          |
| `BFC_E_BADMAGIC` | `EINVAL`    | Invalid container format |
| `BFC_E_EXISTS`   | `EEXIST`    | Entry already exists     |

---

## Security Considerations

### Path Validation

```c
// BFC provides automatic path normalization and traversal protection
// Paths are normalized to prevent "../" attacks
// All paths stored as UTF-8 with canonical form
```

### Encryption Support

```c
// ChaCha20-Poly1305 AEAD encryption
// - 256-bit keys with 96-bit nonces
// - Per-file encryption with unique nonces
// - Authenticated encryption prevents tampering
// - Argon2id key derivation for passwords
// - Metadata (paths, structure) NOT encrypted
```

### Safe Extraction

```c
// Use O_NOFOLLOW to prevent symlink attacks
// Validate parent directories before creation
// CRC32C validation on all read operations
```

---

## Performance Targets

| Operation         | Target Performance             |
| ----------------- | ------------------------------ |
| Container open    | ≤5 ms for 100K entries on NVMe |
| Directory listing | ≤1 ms for ≤1024 entries        |
| Sequential read   | ≥1 GB/s                        |
| Random 4KiB read  | ≥50 MB/s                       |
| File stat()       | ≤0.1 ms (O(log N) lookup)      |

---

## Build Configuration

### Required Dependencies

```bash
# Minimal build
cmake -B build -DCMAKE_BUILD_TYPE=Release

# Full features
cmake -B build \
  -DCMAKE_BUILD_TYPE=Release \
  -DBFC_WITH_ZSTD=ON \      # Compression support
  -DBFC_WITH_SODIUM=ON \    # Encryption support
  -DBFC_WITH_FUSE=ON        # FUSE filesystem support
```

### Link Libraries

```bash
# Link against libbfc
gcc filesystem.c -lbfc -lzstd -lsodium -lfuse3
```

---

## Example Implementation Skeleton

### Basic FUSE Filesystem

```c
#include <fuse3/fuse.h>
#include <bfc.h>

static bfcfs_context_t* fs_ctx;

static int bfcfs_getattr(const char* path, struct stat* stbuf,
                        struct fuse_file_info* fi) {
    bfc_entry_t entry;
    int result = bfc_stat(fs_ctx->container, path, &entry);
    if (result != BFC_OK) {
        return map_bfc_error(result);
    }

    stbuf->st_mode = entry.mode;
    stbuf->st_size = entry.size;
    stbuf->st_mtime = entry.mtime_ns / 1000000000;
    // ... set other stat fields

    return 0;
}

static int bfcfs_read(const char* path, char* buf, size_t size,
                     off_t offset, struct fuse_file_info* fi) {
    size_t bytes_read = bfc_read(fs_ctx->container, path, offset, buf, size);
    return bytes_read;
}

static int bfcfs_readdir(const char* path, void* buf, fuse_fill_dir_t filler,
                        off_t offset, struct fuse_file_info* fi,
                        enum fuse_readdir_flags flags) {
    // Use bfc_list() with callback to populate directory entries
    return bfc_list(fs_ctx->container, path, readdir_callback, buf);
}

static const struct fuse_operations bfcfs_ops = {
    .getattr = bfcfs_getattr,
    .read    = bfcfs_read,
    .readdir = bfcfs_readdir,
    // ... other operations
};
```

---

## Thread Safety

**Important**: BFC is **NOT thread-safe**. For multi-threaded filesystem implementations:

1. Use separate `bfc_t` handles per thread, or
2. Implement proper locking around BFC API calls, or
3. Use a single-threaded event loop design

---

## Limitations for Filesystem Use

1. **Read-only**: BFC containers are immutable after creation
2. **No symlinks**: Only regular files and directories supported
3. **No device files**: No support for special files (block/char devices, FIFOs)
4. **No extended attributes**: POSIX ACLs and xattrs not supported
5. **No hardlinks**: Each file stored separately
6. **Fixed timestamps**: mtime stored, but atime/ctime not tracked

---

## Advanced Features

### Compression Integration

- Transparent compression/decompression
- ZSTD with configurable levels (1-22)
- Per-file compression based on content analysis
- Automatic threshold-based compression

### Encryption Integration

- Per-file ChaCha20-Poly1305 AEAD encryption
- Password-based with Argon2id key derivation
- Raw 32-byte key support
- Transparent encrypt/decrypt in filesystem layer

### Performance Optimizations

- Hardware-accelerated CRC32C validation
- Memory-mapped index for large containers
- 16-byte aligned data structures
- Efficient binary search for file lookup
