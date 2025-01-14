# SPDX-License-Identifier: GPL-2.0
#
# Author: Huacai Chen <chenhuacai@loongson.cn>
# Copyright (C) 2020-2021 Loongson Technology Corporation Limited

KBUILD_DEFCONFIG := loongson3_defconfig

#
# Select the object file format to substitute into the linker script.
#
64bit-tool-archpref	= loongarch64
32bit-tool-archpref	= loongarch32
32bit-bfd		= elf32-loongarch
64bit-bfd		= elf64-loongarch
32bit-emul		= elf32loongarch
64bit-emul		= elf64loongarch

ifdef CONFIG_64BIT
tool-archpref		= $(64bit-tool-archpref)
UTS_MACHINE		:= loongarch64
else
tool-archpref		= $(32bit-tool-archpref)
UTS_MACHINE		:= loongarch32
endif

ifneq ($(SUBARCH),$(ARCH))
  ifeq ($(CROSS_COMPILE),)
    CROSS_COMPILE := $(call cc-cross-prefix, $(tool-archpref)-linux-  $(tool-archpref)-linux-gnu-  $(tool-archpref)-unknown-linux-gnu-)
  endif
endif

cflags-y += $(call cc-option, -mno-check-zero-division)

ifdef CONFIG_64BIT
ld-emul			= $(64bit-emul)
cflags-y		+= -mabi=lp64s
else
ld-emul			= $(32bit-emul)
cflags-y		+= -mabi=ilp32s
endif

all-y			:= vmlinux

#
# GCC uses -G0 -mabicalls -fpic as default.  We don't want PIC in the kernel
# code since it only slows down the whole thing.  At some point we might make
# use of global pointer optimizations but their use of $r2 conflicts with
# the current pointer optimization.
#
cflags-y			+= -pipe
cflags-y			+= -msoft-float
LDFLAGS_vmlinux			+= -static -n -nostdlib
KBUILD_AFLAGS_KERNEL		+= -Wa,-mla-global-with-pcrel
KBUILD_CFLAGS_KERNEL		+= -Wa,-mla-global-with-pcrel
KBUILD_AFLAGS_MODULE		+= -Wa,-mla-global-with-abs
KBUILD_CFLAGS_MODULE		+= -fno-plt -Wa,-mla-global-with-abs,-mla-local-with-abs

cflags-y += -ffreestanding
cflags-y += $(call as-option,-Wa$(comma)-mno-fix-loongson3-llsc,)
cflags-y += -U_LOONGARCH_ISA -D_LOONGARCH_ISA=_LOONGARCH_ISA_LOONGARCH64

load-y		= 0x9000000000200000
bootvars-y	= VMLINUX=vmlinux VMLINUX_LOAD_ADDRESS=$(load-y)

drivers-$(CONFIG_PCI)		+= arch/loongarch/pci/

KBUILD_AFLAGS	+= $(cflags-y)
KBUILD_CFLAGS	+= $(cflags-y)
KBUILD_CPPFLAGS += -DVMLINUX_LOAD_ADDRESS=$(load-y)

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

all:	$(all-y)

# boot
$(boot-y): vmlinux FORCE
	$(Q)$(MAKE) $(build)=arch/loongarch/boot $(bootvars-y) arch/loongarch/boot/$@

CLEAN_FILES += vmlinux

install:
	$(Q)install -D -m 755 vmlinux $(INSTALL_PATH)/vmlinux-$(KERNELRELEASE)
	$(Q)install -D -m 644 .config $(INSTALL_PATH)/config-$(KERNELRELEASE)
	$(Q)install -D -m 644 System.map $(INSTALL_PATH)/System.map-$(KERNELRELEASE)

define archhelp
	echo '  install              - install kernel into $(INSTALL_PATH)'
	echo '  vmlinux.bin          - Raw binary boot image'
	echo
endef
