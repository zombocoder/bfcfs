# BFCFS - BFC Kernel Filesystem Driver

A native Linux kernel filesystem driver for mounting BFC (Binary File Container) images directly without FUSE.

## Current Status: Phase 0 MVP

- ✅ **Module Loading**: Loads and registers as kernel filesystem
- ✅ **Basic Infrastructure**: Mount parsing, index loading, VFS integration
- ✅ **Uncompressed Files**: Can read plain (uncompressed, unencrypted) files
- 🚧 **Compression**: Zstd support planned (Phase 0.2)
- 🚧 **Encryption**: AEAD encryption planned (Phase 0.3)

## Building

### Prerequisites

```bash
# Ensure kernel headers are installed
sudo apt install linux-headers-$(uname -r)
```

### Build Commands

```bash
# Build the module
make

# Clean build artifacts
make clean

# Load module (for testing)
sudo make load

# Unload module
sudo make unload

# Install to system modules directory
sudo make install
```

## Usage

### Basic Mount (uncompressed containers only)

```bash
# Load the module
sudo modprobe bfcfs

# Mount a BFC container
sudo mount -t bfcfs -o source=/path/to/container.bfc /mnt/bfc

# Browse contents
ls -la /mnt/bfc/

# Unmount
sudo umount /mnt/bfc
```

### Mount Options

- `source=PATH` - Path to .bfc container file (required)
- `verify=MODE` - Verification mode: `none`, `shallow`, `deep` (default: `shallow`)
- `noreadahead` - Disable readahead optimization

### Example

```bash
sudo mount -t bfcfs -o source=/tmp/app.bfc,verify=deep /mnt/app
```

## Development

### File Structure

```
bfcfs/
├── include/bfcfs.h     # Core data structures and definitions
├── fs/
│   ├── super.c         # Superblock and module management
│   ├── opts.c          # Mount option parsing
│   ├── index.c         # BFC container index parsing
│   ├── inode.c         # VFS inode operations
│   ├── data.c          # File reading and page cache
│   ├── crypto.c        # Encryption support (stub)
│   └── verify.c        # Data verification
├── Makefile           # Kernel module build
├── Kconfig           # Kernel configuration
└── README.md         # This file
```

### Testing

```bash
# Check if module loaded
lsmod | grep bfcfs

# Check filesystem registration
cat /proc/filesystems | grep bfcfs

# View kernel messages
sudo dmesg | grep bfcfs
```

### Creating Test Containers

Use the BFC CLI tool to create test containers:

```bash
# Create uncompressed container
bfc create test.bfc /path/to/source/

# Create with compression (not yet supported by this driver)
bfc create -c zstd test.bfc /path/to/source/
```

## Implementation Phases

### Phase 0: Foundation (✅ Complete)

- [x] Module infrastructure and VFS registration
- [x] Mount option parsing
- [x] BFC index parsing and validation
- [x] Basic file and directory operations
- [x] Support for uncompressed, unencrypted files

### Phase 0.2: Compression Support (🚧 Planned)

- [ ] Zstd decompression integration
- [ ] Chunked file reading with compression
- [ ] Performance optimization for compressed files

### Phase 0.3: Encryption Support (🚧 Planned)

- [ ] Kernel keyring integration
- [ ] ChaCha20-Poly1305 AEAD decryption
- [ ] Per-chunk encryption/decryption

### Phase 1: Advanced Features (🚧 Future)

- [ ] Symlink support
- [ ] Extended attributes
- [ ] Performance optimizations
- [ ] Advanced verification modes

## Contributing

### Code Style

- Follow Linux kernel coding style
- Use `scripts/checkpatch.pl` to validate patches
- Keep functions focused and well-documented

### Building Against Different Kernels

```bash
# Build for specific kernel version
make KERNELDIR=/lib/modules/6.1.0/build

# Cross-compile (if toolchain available)
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu-
```

## License

GPL v2 - Compatible with Linux kernel licensing

## References

- [BFC Format Specification](./BFC_API_REFERENCE.md)
- [Linux Kernel Module Programming Guide](https://tldp.org/LDP/lkmpg/2.6/html/)
- [Writing Linux Filesystems](https://www.kernel.org/doc/html/latest/filesystems/index.html)
