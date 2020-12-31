// SPDX-License-Identifier: GPL-2.0
/*
 * Support for Kernel relocation at boot time
 *
 * Copyright (C) 2020 Loongson Technology Co., Ltd.
 * Authors: Huacai Chen (chenhuacai@loongson.cn)
 */
#include <asm/bootinfo.h>
#include <asm/fw.h>
#include <asm/sections.h>
#include <asm/setup.h>
#include <linux/elf.h>
#include <linux/kernel.h>
#include <linux/start_kernel.h>
#include <linux/string.h>
#include <linux/printk.h>
#include <linux/panic_notifier.h>

#define RELOCATED(x) ((void *)((long)x + offset))

extern u32 _relocation_start[];	/* End kernel image / start relocation table */
extern u32 _relocation_end[];	/* End relocation table */

extern long __start___ex_table;	/* Start exception table */
extern long __stop___ex_table;	/* End exception table */

static int __init apply_r_loongarch_32_rel(u32 *loc_orig, u32 *loc_new, long offset)
{
	*loc_new += offset;

	return 0;
}

static int __init apply_r_loongarch_64_rel(u32 *loc_orig, u32 *loc_new, long offset)
{
	*(u64 *)loc_new += offset;

	return 0;
}

/*
 * The details about la.abs $r1, x on LoongArch
 *
 * lu12i.w $r1, 0
 * ori     $r1, $r1, 0x0
 * lu32i.d $r1, 0
 * lu52i.d $r1, $r1, 0
 *
 * LoongArch use lu12i.w, ori, lu32i.d, lu52i.d to load a 64bit imm.
 * lu12i.w load bit31~bit12, ori load bit12~bit0,
 * lu32i.d load bit51~bit32, lu32i.d load bit63~bit52
 */
#define ORI_IMMMSK   0xfff
#define ORI_IMMPOS   10
#define LU12I_IMMMSK 0xfffff
#define LU12I_IMMPOS 5
#define LU12I_OFFSET 12
#define LU32I_IMMMSK 0xfffff
#define LU32I_IMMPOS 5
#define LU32I_OFFSET 32
#define LU52I_IMMMSK 0xfff
#define LU52I_IMMPOS 10
#define LU52I_OFFSET 52
#define RD_MASK 0x1f

static int __init apply_r_loongarch_mark_la_rel(u32 *loc_orig, u32 *loc_new, long offset)
{
	unsigned int ins, rd;
	unsigned long long dest;

	ins = loc_new[1];
	rd = ins & RD_MASK;
	dest = (ins >> ORI_IMMPOS) & ORI_IMMMSK;
	ins = loc_new[0];
	dest |= ((ins >> LU12I_IMMPOS) & LU12I_IMMMSK) << LU12I_OFFSET;
	ins = loc_new[2];
	dest |= ((unsigned long long)((ins >> LU32I_IMMPOS) & LU32I_IMMMSK)) << LU32I_OFFSET;
	ins = loc_new[3];
	dest |= ((unsigned long long)((ins >> LU52I_IMMPOS) & LU52I_IMMMSK)) << LU52I_OFFSET;
	dest += offset;

	loc_new[0] = (loc_new[0] & ~(LU12I_IMMMSK << LU12I_IMMPOS)) | (((dest >> LU12I_OFFSET) & LU12I_IMMMSK) << LU12I_IMMPOS);
	loc_new[1] = (loc_new[1] & ~(ORI_IMMMSK << ORI_IMMPOS)) | ((dest & ORI_IMMMSK) << ORI_IMMPOS);
	loc_new[2] = (loc_new[2] & ~(LU32I_IMMMSK << LU32I_IMMPOS)) | (((dest >> LU32I_OFFSET) & LU32I_IMMMSK) << LU32I_IMMPOS);
	loc_new[3] = (loc_new[3] & ~(LU52I_IMMMSK << LU52I_IMMPOS)) | (((dest >> LU52I_OFFSET) & LU52I_IMMMSK) << LU52I_IMMPOS);

	return 0;
}

static int (*reloc_handlers_rel[]) (u32 *, u32 *, long) __initdata = {
	[R_LARCH_32]		= apply_r_loongarch_32_rel,
	[R_LARCH_64]		= apply_r_loongarch_64_rel,
	[R_LARCH_MARK_LA]	= apply_r_loongarch_mark_la_rel,
};

int __init do_relocations(void *kbase_old, void *kbase_new, long offset)
{
	u32 *r;
	u32 *loc_orig;
	u32 *loc_new;
	int type;
	int res;

	for (r = _relocation_start; r < _relocation_end; r++) {
		/* Sentinel for last relocation */
		if (*r == 0)
			break;

		type = (*r >> 24) & 0xff;
		loc_orig = (void *)(kbase_old + ((*r & 0x00ffffff) << 2));
		loc_new = RELOCATED(loc_orig);

		if (reloc_handlers_rel[type] == NULL) {
			/* Unsupported relocation */
			pr_err("Unhandled relocation type %d at 0x%pK\n",
			       type, loc_orig);
			return -ENOEXEC;
		}

		res = reloc_handlers_rel[type](loc_orig, loc_new, offset);
		if (res)
			return res;
	}

	return 0;
}

/*
 * The exception table is filled in by the relocs tool after vmlinux is linked.
 * It must be relocated separately since there will not be any relocation
 * information for it filled in by the linker.
 */
static int __init relocate_exception_table(long offset)
{
#ifdef CONFIG_BUILDTIME_TABLE_SORT
	unsigned long *etable_start, *etable_end, *e;

	etable_start = RELOCATED(&__start___ex_table);
	etable_end = RELOCATED(&__stop___ex_table);

	for (e = etable_start; e < etable_end; e++)
		*e += offset;
#endif
	return 0;
}

#ifdef CONFIG_RANDOMIZE_BASE

static inline __init unsigned long rotate_xor(unsigned long hash,
					      const void *area, size_t size)
{
	size_t i, diff;
	const typeof(hash) *ptr = PTR_ALIGN(area, sizeof(hash));

	diff = (void *)ptr - area;
	if (unlikely(size < diff + sizeof(hash)))
		return hash;

	size = ALIGN_DOWN(size - diff, sizeof(hash));

	for (i = 0; i < size / sizeof(hash); i++) {
		/* Rotate by odd number of bits and XOR. */
		hash = (hash << ((sizeof(hash) * 8) - 7)) | (hash >> 7);
		hash ^= ptr[i];
	}

	return hash;
}

static inline __init unsigned long get_random_boot(void)
{
	unsigned long entropy = random_get_entropy();
	unsigned long hash = 0;

	/* Attempt to create a simple but unpredictable starting entropy. */
	hash = rotate_xor(hash, linux_banner, strlen(linux_banner));

	/* Add in any runtime entropy we can get */
	hash = rotate_xor(hash, &entropy, sizeof(entropy));

	return hash;
}

static inline __init bool kaslr_disabled(void)
{
	char *str;

#if defined(CONFIG_CMDLINE_BOOL)
	const char *builtin_cmdline = CONFIG_CMDLINE;

	str = strstr(builtin_cmdline, "nokaslr");
	if (str == builtin_cmdline ||
	    (str > builtin_cmdline && *(str - 1) == ' '))
		return true;
#endif
	str = strstr(arcs_cmdline, "nokaslr");
	if (str == arcs_cmdline || (str > arcs_cmdline && *(str - 1) == ' '))
		return true;

	return false;
}

static inline void __init *determine_relocation_address(void)
{
	/* Choose a new address for the kernel */
	unsigned long kernel_length;
	void *dest = &_text;
	unsigned long offset;

	if (kaslr_disabled())
		return dest;

	kernel_length = (long)_end - (long)(&_text);

	offset = get_random_boot() << 16;
	offset &= (CONFIG_RANDOMIZE_BASE_MAX_OFFSET - 1);
	if (offset < kernel_length)
		offset += ALIGN(kernel_length, 0xffff);

	return RELOCATED(dest);
}

#else

static inline void __init *determine_relocation_address(void)
{
	/*
	 * Choose a new address for the kernel
	 * For now we'll hard code the destination
	 */
	return (void *)(CAC_BASE + 0x02000000);
}

#endif

static inline int __init relocation_addr_valid(void *loc_new)
{
	if ((unsigned long)loc_new & 0x0000ffff) {
		/* Inappropriately aligned new location */
		return 0;
	}
	if ((unsigned long)loc_new < (unsigned long)&_end) {
		/* New location overlaps original kernel */
		return 0;
	}
	return 1;
}

static inline void __init update_kaslr_offset(unsigned long *addr, long offset)
{
	unsigned long *new_addr = (unsigned long *)RELOCATED(addr);

	*new_addr = (unsigned long)offset;
}

void *__init relocate_kernel(void)
{
	void *loc_new;
	unsigned long kernel_length;
	unsigned long bss_length;
	long offset = 0;
	int res = 1;
	/* Default to original kernel entry point */
	void *kernel_entry = start_kernel;

	/* Get the command line */
	fw_init_cmdline();

	kernel_length = (long)(&_relocation_start) - (long)(&_text);
	bss_length = (long)&__bss_stop - (long)&__bss_start;

	loc_new = determine_relocation_address();

	/* Sanity check relocation address */
	if (relocation_addr_valid(loc_new))
		offset = (unsigned long)loc_new - (unsigned long)(&_text);

	/* Reset the command line now so we don't end up with a duplicate */
	arcs_cmdline[0] = '\0';

	if (offset) {
		/* Copy the kernel to it's new location */
		memcpy(loc_new, &_text, kernel_length);

		/* Perform relocations on the new kernel */
		res = do_relocations(&_text, loc_new, offset);
		if (res < 0)
			goto out;

		/* Sync the caches ready for execution of new kernel */
		asm volatile (
		"	ibar 0					\n"
		"	dbar 0					\n");

		res = relocate_exception_table(offset);
		if (res < 0)
			goto out;

		/*
		 * The original .bss has already been cleared, and
		 * some variables such as command line parameters
		 * stored to it so make a copy in the new location.
		 */
		memcpy(RELOCATED(&__bss_start), &__bss_start, bss_length);

		/* The current thread is now within the relocated image */
		__current_thread_info = RELOCATED(__current_thread_info);

		/* Return the new kernel's entry point */
		kernel_entry = RELOCATED(start_kernel);

		update_kaslr_offset(&__kaslr_offset, offset);
	}
out:
	return kernel_entry;
}

/*
 * Show relocation information on panic.
 */
void show_kernel_relocation(const char *level)
{
	if (__kaslr_offset > 0) {
		printk(level);
		pr_cont("Kernel relocated by 0x%pK\n", (void *)__kaslr_offset);
		pr_cont(" .text @ 0x%pK\n", _text);
		pr_cont(" .data @ 0x%pK\n", _sdata);
		pr_cont(" .bss  @ 0x%pK\n", __bss_start);
	}
}

static int kernel_location_notifier_fn(struct notifier_block *self,
				       unsigned long v, void *p)
{
	show_kernel_relocation(KERN_EMERG);
	return NOTIFY_DONE;
}

static struct notifier_block kernel_location_notifier = {
	.notifier_call = kernel_location_notifier_fn
};

static int __init register_kernel_offset_dumper(void)
{
	atomic_notifier_chain_register(&panic_notifier_list,
				       &kernel_location_notifier);
	return 0;
}
__initcall(register_kernel_offset_dumper);
