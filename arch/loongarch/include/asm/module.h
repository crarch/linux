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
#ifdef CONFIG_DYNAMIC_FTRACE
	void *ftrace_trampolines[1 + CONFIG_DYNAMIC_FTRACE_WITH_REGS];
#endif
};

#ifndef CONFIG_DYNAMIC_FTRACE
static inline int apply_ftrace_tramp(struct module *mod, void *addr, size_t size)
{
	return 0;
}
#else
extern int apply_ftrace_tramp(struct module *mod, void *addr, size_t size);
#endif

#endif /* _ASM_MODULE_H */
