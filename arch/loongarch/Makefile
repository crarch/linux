# SPDX-License-Identifier: GPL-2.0
#
# Author: Huacai Chen <chenhuacai@loongson.cn>
# Copyright (C) 2020 Loongson Technology Corporation Limited

archscripts: scripts_basic
	$(Q)$(MAKE) $(build)=arch/loongarch/tools elf-entry
	$(Q)$(MAKE) $(build)=arch/loongarch/boot/tools relocs

KBUILD_DEFCONFIG := loongson3_defconfig
KBUILD_DTBS      := dtbs

#
# Select the object file format to substitute into the linker script.
#
64bit-tool-archpref	= loongarch64
32bit-bfd		= elf32-loongarch
64bit-bfd		= elf64-loongarch
32bit-emul		= elf32loongarch
64bit-emul		= elf64loongarch

ifdef CONFIG_64BIT
tool-archpref		= $(64bit-tool-archpref)
UTS_MACHINE		:= loongarch64
endif

ifneq ($(SUBARCH),$(ARCH))
  ifeq ($(CROSS_COMPILE),)
    CROSS_COMPILE := $(call cc-cross-prefix, $(tool-archpref)-linux-  $(tool-archpref)-linux-gnu-  $(tool-archpref)-unknown-linux-gnu-)
  endif
endif

ifdef CONFIG_DYNAMIC_FTRACE
  KBUILD_CPPFLAGS += -DCC_USING_PATCHABLE_FUNCTION_ENTRY
  CC_FLAGS_FTRACE := -fpatchable-function-entry=2
endif

cflags-y += $(call cc-option, -mno-check-zero-division)

ifdef CONFIG_64BIT
ld-emul			= $(64bit-emul)
cflags-y		+= -mabi=lp64
endif

all-y			:= vmlinux
all-$(CONFIG_SYS_SUPPORTS_ZBOOT)+= vmlinuz

#
# GCC uses -G0 -mabicalls -fpic as default.  We don't want PIC in the kernel
# code since it only slows down the whole thing.  At some point we might make
# use of global pointer optimizations but their use of $r2 conflicts with
# the current pointer optimization.
#
cflags-y			+= -G0 -pipe
cflags-y			+= -msoft-float
LDFLAGS_vmlinux			+= -G0 -static -n -nostdlib
KBUILD_AFLAGS_KERNEL		+= -Wa,-mla-global-with-pcrel
KBUILD_CFLAGS_KERNEL		+= -Wa,-mla-global-with-pcrel
KBUILD_AFLAGS_MODULE		+= -Wa,-mla-global-with-abs
KBUILD_CFLAGS_MODULE		+= -fno-plt -Wa,-mla-global-with-abs,-mla-local-with-abs

ifeq ($(CONFIG_RELOCATABLE),y)
LDFLAGS_vmlinux		+= --emit-relocs
endif

cflags-y += -ffreestanding

#
# Kernel compression
#
ifdef CONFIG_SYS_SUPPORTS_ZBOOT
KBUILD_IMAGE	= vmlinuz
else
KBUILD_IMAGE	= vmlinux
endif

drivers-$(CONFIG_LOONGARCH_CRC32_SUPPORT) += arch/loongarch/crypto/

#
# Board-dependent options and extra files
#
include arch/loongarch/Kbuild.platforms

ifdef CONFIG_PHYSICAL_START
load-y				= $(CONFIG_PHYSICAL_START)
endif

entry-y				= $(shell $(objtree)/arch/loongarch/tools/elf-entry vmlinux)
drivers-$(CONFIG_PCI)		+= arch/loongarch/pci/

KBUILD_AFLAGS	+= $(cflags-y)
KBUILD_CFLAGS	+= $(cflags-y)
KBUILD_CPPFLAGS += -DVMLINUX_LOAD_ADDRESS=$(load-y)

bootvars-y	= VMLINUX_LOAD_ADDRESS=$(load-y) \
		  VMLINUX_ENTRY_ADDRESS=$(entry-y) PLATFORM="$(platform-y)"

ifdef CONFIG_64BIT
bootvars-y	+= ADDR_BITS=64
endif

# This is required to get dwarf unwinding tables into .debug_frame
# instead of .eh_frame so we don't discard them.
KBUILD_CFLAGS += -fno-asynchronous-unwind-tables
KBUILD_CFLAGS += -isystem $(shell $(CC) -print-file-name=include)

KBUILD_LDFLAGS	+= -m $(ld-emul)

ifdef CONFIG_LOONGARCH
CHECKFLAGS += $(shell $(CC) $(KBUILD_CFLAGS) -dM -E -x c /dev/null | \
	egrep -vw '__GNUC_(MINOR_|PATCHLEVEL_)?_' | \
	sed -e "s/^\#define /-D'/" -e "s/ /'='/" -e "s/$$/'/" -e 's/\$$/&&/g')
endif

head-y := arch/loongarch/kernel/head.o

libs-y += arch/loongarch/lib/

# suspend and hibernation support
drivers-$(CONFIG_PM)	+= arch/loongarch/power/

ifeq ($(KBUILD_EXTMOD),)
prepare: vdso_prepare
vdso_prepare: prepare0
	$(Q)$(MAKE) $(build)=arch/loongarch/vdso include/generated/vdso-offsets.h
endif

PHONY += vdso_install
vdso_install:
	$(Q)$(MAKE) $(build)=arch/loongarch/vdso $@

# boot image targets (arch/loongarch/boot/)
boot-y := vmlinux.bin

# compressed boot image targets (arch/loongarch/boot/compressed/)
bootz-y			:= vmlinuz
bootz-y			+= vmlinuz.bin

all:	$(all-y) $(KBUILD_DTBS)

# boot
$(boot-y): vmlinux FORCE
	$(Q)$(MAKE) $(build)=arch/loongarch/boot VMLINUX=vmlinux \
		$(bootvars-y) arch/loongarch/boot/$@

ifdef CONFIG_SYS_SUPPORTS_ZBOOT
# boot/compressed
$(bootz-y): vmlinux FORCE
	$(Q)$(MAKE) $(build)=arch/loongarch/boot/compressed \
		$(bootvars-y) 64bit-bfd=$(64bit-bfd) $@
else
vmlinuz: FORCE
	@echo '   CONFIG_SYS_SUPPORTS_ZBOOT is not enabled'
	/bin/false
endif

CLEAN_FILES += vmlinux

# device-trees
core-y += arch/loongarch/boot/dts/

install:
	$(Q)install -D -m 755 vmlinux $(INSTALL_PATH)/vmlinux-$(KERNELRELEASE)
ifdef CONFIG_SYS_SUPPORTS_ZBOOT
	$(Q)install -D -m 755 vmlinuz $(INSTALL_PATH)/vmlinuz-$(KERNELRELEASE)
endif
	$(Q)install -D -m 644 .config $(INSTALL_PATH)/config-$(KERNELRELEASE)
	$(Q)install -D -m 644 System.map $(INSTALL_PATH)/System.map-$(KERNELRELEASE)

archclean:
	$(Q)$(MAKE) $(clean)=arch/loongarch/boot
	$(Q)$(MAKE) $(clean)=arch/loongarch/boot/compressed
	$(Q)$(MAKE) $(clean)=arch/loongarch/boot/tools
	$(Q)$(MAKE) $(clean)=arch/loongarch/tools

define archhelp
	echo '  install              - install kernel into $(INSTALL_PATH)'
	echo '  vmlinux.bin          - Raw binary boot image'
	echo '  vmlinuz              - Compressed boot(zboot) image'
	echo '  vmlinuz.bin          - Raw binary zboot image'
	echo '  dtbs                 - Device-tree blobs for enabled boards'
	echo '  dtbs_install         - Install dtbs to $(INSTALL_DTBS_PATH)'
	echo
endef
