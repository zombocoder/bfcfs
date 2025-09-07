# SPDX-License-Identifier: Apache-2.0
# BFC Filesystem Kernel Module Makefile

obj-$(CONFIG_BFCFS) += bfcfs.o

bfcfs-y := fs/super.o \
           fs/opts.o \
           fs/index.o \
           fs/inode.o \
           fs/data.o \
           fs/crypto.o \
           fs/verify.o

ccflags-y += -I$(src)/include

# Development build (when built out-of-tree)
ifeq ($(KERNELRELEASE),)

KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) CONFIG_BFCFS=m modules
	@echo "Module built: $(PWD)/bfcfs.ko"

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
	rm -f *.mod.c .*.cmd .tmp_versions
	find . -name "*.o" -delete 2>/dev/null || true
	find . -name ".*.cmd" -delete 2>/dev/null || true
	rm -rf .tmp_versions

install: default
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules_install

help:
	@echo "Available targets:"
	@echo "  default  - Build the bfcfs kernel module"
	@echo "  clean    - Clean build artifacts"  
	@echo "  install  - Install the module to system"
	@echo "  load     - Load the module (requires sudo)"
	@echo "  unload   - Unload the module (requires sudo)"

load: default
	sudo insmod bfcfs.ko
	@echo "Module loaded. Check dmesg for status."

unload:
	sudo rmmod bfcfs
	@echo "Module unloaded."

.PHONY: default clean install help load unload

endif