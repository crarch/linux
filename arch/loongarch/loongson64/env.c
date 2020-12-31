// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020 Loongson Technology Co., Ltd.
 * Author: Huacai Chen <chenhuacai@loongson.cn>
 *
 * This program is free software; you can redistribute	it and/or modify it
 * under  the terms of	the GNU General	 Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 */
#include <linux/export.h>
#include <linux/acpi.h>
#include <linux/efi.h>
#include <asm/early_ioremap.h>
#include <asm/fw.h>
#include <asm/time.h>
#include <asm/bootinfo.h>
#include <loongson.h>

struct boot_params *efi_bp;
struct loongsonlist_mem_map *loongson_mem_map;
struct loongsonlist_vbios *pvbios;
struct loongson_system_configuration loongson_sysconf;
EXPORT_SYMBOL(loongson_sysconf);

u64 loongson_chipcfg[MAX_PACKAGES];
u64 loongson_chiptemp[MAX_PACKAGES];
u64 loongson_freqctrl[MAX_PACKAGES];
unsigned long long smp_group[MAX_PACKAGES];

static void __init register_addrs_set(u64 *registers, const u64 addr, int num)
{
	u64 i;

	for (i = 0; i < num; i++) {
		*registers = (i << 44) | addr;
		registers++;
	}
}

static u8 ext_listhdr_checksum(u8 *buffer, u32 length)
{
	u8 sum = 0;
	u8 *end = buffer + length;

	while (buffer < end) {
		sum = (u8)(sum + *(buffer++));
	}

	return (sum);
}

static int parse_mem(struct _extention_list_hdr *head)
{
	loongson_mem_map = (struct loongsonlist_mem_map *)head;

	if (ext_listhdr_checksum((u8 *)loongson_mem_map, head->length)) {
		printk("mem checksum error\n");
		return -EPERM;
	}

	return 0;
}

static int parse_vbios(struct _extention_list_hdr *head)
{
	pvbios = (struct loongsonlist_vbios *)head;

	if (ext_listhdr_checksum((u8 *)pvbios, head->length)) {
		printk("vbios_addr checksum error\n");
		return -EPERM;
	}

	loongson_sysconf.vgabios_addr =
		(u64)early_memremap_ro(pvbios->vbios_addr, 64);

	return 0;
}

static int parse_screeninfo(struct _extention_list_hdr *head)
{
	struct loongsonlist_screeninfo *pscreeninfo;

	pscreeninfo = (struct loongsonlist_screeninfo *)head;
	if (ext_listhdr_checksum((u8 *)pscreeninfo, head->length)) {
		printk("screeninfo_addr checksum error\n");
		return -EPERM;
	}

	memcpy(&screen_info, &pscreeninfo->si, sizeof(screen_info));

	return 0;
}

static int parse_extlist(struct boot_params *bp)
{
	unsigned long next_offset;
	struct _extention_list_hdr *fhead;

	fhead = (struct _extention_list_hdr *)((void *)bp + bp->extlist_offset);
	if (fhead == NULL) {
		printk("the ext struct is empty!\n");
		return -1;
	}

	do {
		next_offset = fhead->next_offset;
		if (memcmp(&(fhead->signature), LOONGSON_MEM_SIGNATURE, 3) == 0) {
			if (parse_mem(fhead) != 0) {
				printk("parse mem failed\n");
				return -EPERM;
			}
		} else if (memcmp(&(fhead->signature), LOONGSON_VBIOS_SIGNATURE, 5) == 0) {
			if (parse_vbios(fhead) != 0) {
				printk("parse vbios failed\n");
				return -EPERM;
			}
		} else if (memcmp(&(fhead->signature), LOONGSON_SCREENINFO_SIGNATURE, 5) == 0) {
			if (parse_screeninfo(fhead) != 0) {
				printk("parse screeninfo failed\n");
				return -EPERM;
			}
		}
		fhead = (struct _extention_list_hdr *)((void *)bp + next_offset);
	} while (next_offset);

	return 0;
}

static void __init parse_flags(u64 flags)
{
	if (flags & BPI_FLAGS_UEFI_SUPPORTED)
		set_bit(EFI_BOOT, &efi.flags);
	else
		clear_bit(EFI_BOOT, &efi.flags);
}

static int get_bpi_version(void *signature)
{
	char data[8];
	int r, version = 0;

	memset(data, 0, 8);
	memcpy(data, signature + 4, 4);
	r = kstrtoint(data, 10, &version);

	if (r < 0 || version < BPI_VERSION_V1)
		panic("Fatal error, invalid BPI version: %d\n", version);

	if (version >= BPI_VERSION_V2)
		parse_flags(efi_bp->flags);

	return version;
}

void __init fw_init_environ(void)
{
	efi_bp = (struct boot_params *)_fw_envp;
	loongson_sysconf.bpi_ver = get_bpi_version(&efi_bp->signature);

	register_addrs_set(smp_group, TO_UNCAC(0x1fe01000), 16);
	register_addrs_set(loongson_chipcfg, TO_UNCAC(0x1fe00180), 16);
	register_addrs_set(loongson_chiptemp, TO_UNCAC(0x1fe0019c), 16);
	register_addrs_set(loongson_freqctrl, TO_UNCAC(0x1fe001d0), 16);

	if (parse_extlist(efi_bp))
		printk("Scan bootparm failed\n");
}

static int __init init_cpu_fullname(void)
{
	int cpu;

	if (loongson_sysconf.cpuname && !strncmp(loongson_sysconf.cpuname, "Loongson", 8)) {
		for(cpu = 0; cpu < NR_CPUS; cpu++)
			__cpu_full_name[cpu] = loongson_sysconf.cpuname;
	}
	return 0;
}
arch_initcall(init_cpu_fullname);
