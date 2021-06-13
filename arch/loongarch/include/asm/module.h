/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2020 Loongson Technology Corporation Limited
 */
#ifndef _ASM_MODULE_H
#define _ASM_MODULE_H

#include <asm-generic/module.h>
#include <asm/orc_types.h>

#define RELA_STACK_DEPTH 16

struct mod_arch_specific {
#ifdef CONFIG_UNWINDER_ORC
	unsigned int num_orcs;
	int *orc_unwind_ip;
	struct orc_entry *orc_unwind;
#endif
};

#endif /* _ASM_MODULE_H */
