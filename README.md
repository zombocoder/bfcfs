# BFCFS - BFC Kernel Filesystem Driver

[![Build Status](https://github.com/zombocoder/bfcfs/workflows/Build%20bfcfs%20(headers%206.8.0-49-generic)/badge.svg)](https://github.com/zombocoder/bfcfs/actions)
[![License: GPL v2](https://img.shields.io/badge/License-GPL_v2-blue.svg)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)
[![Kernel Support](https://img.shields.io/badge/Kernel-6.8.x+-green.svg)](https://kernel.org/)
[![Status](https://img.shields.io/badge/Status-Stable-brightgreen.svg)](#current-status-phase-0-mvp)

A native Linux kernel filesystem driver for mounting BFC (Binary File Container) images directly without FUSE.

## Features

- 🚀 **Native Performance**: Direct kernel integration, no FUSE overhead
- 📁 **Full Directory Support**: Complete directory tree navigation and listing
- 📄 **File Reading**: Accurate and complete file content access
- 🔒 **Memory Safe**: Proper VFS integration with clean resource management
- ⚡ **Direct I/O**: Efficient file reading bypassing page cache complications
- 🛡️ **Crash-Free**: Stable mount/unmount operations without kernel crashes
- 🔧 **Standard Tools**: Works with all standard Linux file utilities (`ls`, `cat`, `cp`, etc.)

## Current Status: Phase 0 MVP - ✅ **STABLE**

The BFCFS kernel module is now fully functional for basic BFC container operations:

- ✅ **Module Loading/Unloading**: Clean insertion and removal from kernel
- ✅ **Mount/Unmount Operations**: Proper VFS integration without crashes
- ✅ **Directory Operations**: Full directory listing and navigation
- ✅ **File Reading**: Complete and accurate file content access
- ✅ **Uncompressed Files**: Full support for plain (uncompressed, unencrypted) files
- ✅ **VFS Integration**: Proper inode allocation and memory management
- 🚧 **Compression**: Zstd support planned (Phase 0.2)
- 🚧 **Encryption**: AEAD encryption planned (Phase 0.3)

## Building

### Prerequisites

**Important**: This filesystem driver requires **Linux kernel 6.8.x or newer** due to VFS API changes.

```bash
# For Ubuntu 22.04, install kernel 6.8.x
sudo apt update
sudo apt install linux-image-6.8.0-49-generic linux-headers-6.8.0-49-generic
sudo reboot

# After reboot, ensure kernel headers are installed
sudo apt install linux-headers-$(uname -r)

# Verify kernel version
uname -r  # Should show 6.8.x
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

### Quick Start Example

```bash
# Load the module
sudo insmod bfcfs.ko

# Mount a BFC container
sudo mount -t bfcfs -o source=/path/to/container.bfc none /mnt/bfc

# Browse contents
ls -la /mnt/bfc/
cat /mnt/bfc/some-file.txt

# Unmount cleanly
sudo umount /mnt/bfc

# Unload module
sudo rmmod bfcfs
```

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

## Module Signing (Optional)

By default, loading the BFC module will show a "module verification failed" warning and taint the kernel. This is normal for out-of-tree modules but can be avoided by signing the module.

### Method 1: Self-Signed Certificate (Recommended)

```bash
# Generate signing certificate and private key
openssl req -new -x509 -newkey rsa:2048 -keyout MOK.priv -outform DER -out MOK.der \
    -nodes -days 36500 -subj "/CN=BFC Module/"

# Sign the compiled module
sudo /usr/src/linux-headers-$(uname -r)/scripts/sign-file sha512 MOK.priv MOK.der bfcfs.ko

# Import certificate to Machine Owner Key (MOK) list
sudo mokutil --import MOK.der
# Enter a password when prompted (e.g., "bfcmodule")

# Reboot and enroll the key
sudo reboot
```

**During boot:**
1. UEFI will prompt for MOK enrollment
2. Select "Enroll MOK" → "Continue"  
3. Enter the password you set above
4. Reboot to complete enrollment

**After enrollment:**
```bash
# Load the signed module (no more tainted kernel warnings)
sudo insmod bfcfs.ko

# Verify signing status
modinfo bfcfs.ko | grep sig
```

### Method 2: Disable Signature Verification

Alternative approach - add kernel parameter to disable module signature checking:

```bash
# Edit GRUB configuration
sudo nano /etc/default/grub

# Add to GRUB_CMDLINE_LINUX_DEFAULT:
GRUB_CMDLINE_LINUX_DEFAULT="... module.sig_enforce=0"

# Update GRUB and reboot
sudo update-grub
sudo reboot
```

### Verification

Check if module is properly signed:
```bash
modinfo bfcfs.ko | grep sig
# Should show: sig_id, signer, sig_key, sig_hashalgo, signature
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

### Phase 0: Foundation (✅ **COMPLETED**)

- [x] Module infrastructure and VFS registration
- [x] Mount option parsing and validation  
- [x] BFC container format parsing and index loading
- [x] Proper VFS inode allocation and memory management
- [x] Directory operations (listing, lookup, navigation)
- [x] File reading operations with direct I/O
- [x] Clean mount/unmount without kernel crashes
- [x] Support for uncompressed, unencrypted files
- [x] Synthetic root directory handling

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

**Note**: Only kernel 6.8.x and newer are supported.

```bash
# Build for specific kernel version (6.8.x+ only)
make KERNELDIR=/lib/modules/6.8.0-49/build

# Cross-compile (if toolchain available, 6.8.x+ only)
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu-
```

## License

GPL v2 - Compatible with Linux kernel licensing

## References

- [BFC Format Specification](./BFC_API_REFERENCE.md)
- [Linux Kernel Module Programming Guide](https://tldp.org/LDP/lkmpg/2.6/html/)
- [Writing Linux Filesystems](https://www.kernel.org/doc/html/latest/filesystems/index.html)
