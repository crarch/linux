// SPDX-License-Identifier: GPL-2.0
/*
 * Based on arch/arm64/kernel/ftrace.c
 *
 * Copyright (C) 2013 Linaro Limited
 * Copyright (C) 2020 Loongson Technology Corporation Limited
 */

#include <linux/kprobes.h>
#include <linux/ftrace.h>
#include <linux/uaccess.h>

#include <asm/inst.h>
#include <asm/module.h>

static int ftrace_modify_code(unsigned long pc, u32 old, u32 new,
			      bool validate)
{
	u32 replaced;

	if (validate) {
		if (larch_insn_read((void *)pc, &replaced))
			return -EFAULT;

		if (replaced != old)
			return -EINVAL;
	}

	if (larch_insn_patch_text((void *)pc, new))
		return -EPERM;

	return 0;
}

int ftrace_update_ftrace_func(ftrace_func_t func)
{
	unsigned long pc;
	u32 new;

	pc = (unsigned long)&ftrace_call;
	new = larch_insn_gen_bl(pc, (unsigned long)func);

	return ftrace_modify_code(pc, 0, new, false);
}

/*
 * The compiler has inserted 2 NOPs before the regular function prologue.
 * T series registers are available and safe because of LoongArch psABI.
 *
 * At runtime, replace nop with bl to enable ftrace call and replace bl with
 * nop to disable ftrace call. The bl requires us to save the original RA value,
 * so here it saves RA at t0.
 * details are:
 *
 * | Compiled   |       Disabled         |        Enabled         |
 * +------------+------------------------+------------------------+
 * | nop        | move     t0, ra        | move     t0, ra        |
 * | nop        | nop                    | bl      ftrace_caller  |
 * | func_body  | func_body              | func_body              |
 *
 * The RA value will be recovered by ftrace_regs_entry, and restored into RA
 * before returning to the regular function prologue. When a function is not
 * being traced, the move t0, ra is not harmful.
 */

int ftrace_init_nop(struct module *mod, struct dyn_ftrace *rec)
{
	unsigned long pc;
	u32 old, new;

	pc = rec->ip;
	old = larch_insn_gen_nop();
	new = larch_insn_gen_move(LOONGARCH_GPR_T0, LOONGARCH_GPR_RA);

	return ftrace_modify_code(pc, old, new, true);
}

static inline int __get_mod(struct module **mod, unsigned long addr)
{
	preempt_disable();
	*mod = __module_text_address(addr);
	preempt_enable();

	if (WARN_ON(!(*mod)))
		return -EINVAL;

	return 0;
}

static inline int __get_mod_caller(struct module *mod,
				  void *caller, unsigned long *addr)
{
	if (caller == ftrace_caller) {
		*addr = (unsigned long)mod->arch.ftrace_trampolines[0];
		return 0;
	}

#ifdef CONFIG_DYNAMIC_FTRACE_WITH_REGS
	if (caller == ftrace_regs_caller) {
		*addr = (unsigned long)mod->arch.ftrace_trampolines[1];
		return 0;
	}
#endif

	pr_err("ftrace: no trampoline for %ps\n", caller);
	return -EINVAL;
}

int ftrace_make_call(struct dyn_ftrace *rec, unsigned long addr)
{
	unsigned long pc;
	long offset;
	u32 old, new;

	pc = rec->ip + LOONGARCH_INSN_SIZE;
	offset = (long)pc - (long)addr;

	if (offset < -SZ_128M || offset >= SZ_128M) {
		int ret;
		struct module *mod;

		ret = __get_mod(&mod, pc);
		if (ret)
			return ret;

		ret = __get_mod_caller(mod, (void *)addr, &addr);
		if (ret)
			return ret;
	}

	old = larch_insn_gen_nop();
	new = larch_insn_gen_bl(pc, addr);

	return ftrace_modify_code(pc, old, new, true);
}

int ftrace_make_nop(struct module *mod, struct dyn_ftrace *rec,
		    unsigned long addr)
{
	unsigned long pc;
	long offset;
	u32 old, new;

	pc = rec->ip + LOONGARCH_INSN_SIZE;
	offset = (long)pc - (long)addr;

	if (offset < -SZ_128M || offset >= SZ_128M) {
		int ret;
		struct module *mod;

		ret = __get_mod(&mod, pc);
		if (ret)
			return ret;

		ret = __get_mod_caller(mod, (void *)addr, &addr);
		if (ret)
			return ret;
	}

	new = larch_insn_gen_nop();
	old = larch_insn_gen_bl(pc, addr);

	return ftrace_modify_code(pc, old, new, true);
}

#ifdef CONFIG_DYNAMIC_FTRACE_WITH_REGS
int ftrace_modify_call(struct dyn_ftrace *rec, unsigned long old_addr,
			unsigned long addr)
{
	unsigned long pc;
	long offset;
	u32 old, new;

	pc = rec->ip + LOONGARCH_INSN_SIZE;
	offset = (long)pc - (long)addr;

	if (offset < -SZ_128M || offset >= SZ_128M) {
		int ret;
		struct module *mod;

		ret = __get_mod(&mod, pc);
		if (ret)
			return ret;

		ret = __get_mod_caller(mod, (void *)addr, &addr);
		if (ret)
			return ret;

		ret = __get_mod_caller(mod, (void *)old_addr, &old_addr);
		if (ret)
			return ret;
	}

	old = larch_insn_gen_bl(pc, old_addr);
	new = larch_insn_gen_bl(pc, addr);

	return ftrace_modify_code(pc, old, new, true);
}
#endif /* CONFIG_DYNAMIC_FTRACE_WITH_REGS */

void arch_ftrace_update_code(int command)
{
	command |= FTRACE_MAY_SLEEP;
	ftrace_modify_all_code(command);
}

int __init ftrace_dyn_arch_init(void)
{
	return 0;
}

static inline int patch_tramp(struct module_ftrace_tramp *p, void *addr)
{
	u32 addu16id, lu32id, lu52id, jirl;
	enum loongarch_gpr zero = LOONGARCH_GPR_ZERO;
	enum loongarch_gpr t1 = LOONGARCH_GPR_T1;
	unsigned long pos = (unsigned long)addr;

	addu16id = larch_insn_gen_addu16id(t1, zero, ADDR_IMM(pos, ADDU16ID));
	lu32id = larch_insn_gen_lu32id(t1, ADDR_IMM(pos, LU32ID));
	lu52id = larch_insn_gen_lu52id(t1, t1, ADDR_IMM(pos, LU52ID));
	jirl = larch_insn_gen_jirl(zero, t1, 0, (pos & 0xffff));

	return larch_insn_patch_text(&p->addu16id, addu16id) ||
		  larch_insn_patch_text(&p->lu32id, lu32id) ||
		  larch_insn_patch_text(&p->lu52id, lu52id) ||
		  larch_insn_patch_text(&p->jirl, jirl);

	return 0;
}

int apply_ftrace_tramp(struct module *mod, void *addr, size_t size)
{
	int ret;
	struct module_ftrace_tramp *p = addr;

	/*
	 * Add 2 module_ftrace_tramps for calling ftrace_caller
	 * and ftrace_regs_caller. So that we can only change bl
	 * to enable or disable dynamic ftrace.
	 */
	if (WARN_ON(size != 2 * sizeof(struct module_ftrace_tramp)))
		return -EINVAL;

	ret = patch_tramp(p, ftrace_caller);
	if (ret)
		return -EINVAL;

	mod->arch.ftrace_trampolines[0] = p;

#ifdef CONFIG_DYNAMIC_FTRACE_WITH_REGS
	ret = patch_tramp(p + 1, ftrace_regs_caller);
	if (ret)
		return ret;

	mod->arch.ftrace_trampolines[1] = p + 1;
#endif

	return 0;
}

#ifdef CONFIG_FUNCTION_GRAPH_TRACER
extern void ftrace_graph_call(void);

void prepare_ftrace_return(unsigned long self_addr, unsigned long *parent)
{
	unsigned long return_hooker = (unsigned long)&return_to_handler;
	unsigned long old;

	if (unlikely(atomic_read(&current->tracing_graph_pause)))
		return;

	old = *parent;

	if (!function_graph_enter(old, self_addr, 0, parent))
		*parent = return_hooker;
}

static int ftrace_modify_graph_caller(bool enable)
{
	unsigned long pc, func;
	u32 branch, nop;

	pc = (unsigned long)&ftrace_graph_call;
	func = (unsigned long)&ftrace_graph_caller;

	branch = larch_insn_gen_b(pc, func);
	nop = larch_insn_gen_nop();

	if (enable)
		return ftrace_modify_code(pc, nop, branch, true);
	else
		return ftrace_modify_code(pc, branch, nop, true);
}

int ftrace_enable_ftrace_graph_caller(void)
{
	return ftrace_modify_graph_caller(true);
}

int ftrace_disable_ftrace_graph_caller(void)
{
	return ftrace_modify_graph_caller(false);
}
#endif /* CONFIG_FUNCTION_GRAPH_TRACER */

#ifdef CONFIG_KPROBES_ON_FTRACE
/* Ftrace callback handler for kprobes -- called under preepmt disabed */
void kprobe_ftrace_handler(unsigned long ip, unsigned long parent_ip,
			   struct ftrace_ops *ops, struct ftrace_regs *fregs)
{
	int bit;
	struct pt_regs *regs;
	struct kprobe *p;
	struct kprobe_ctlblk *kcb;

	bit = ftrace_test_recursion_trylock(ip, parent_ip);
	if (bit < 0)
		return;

	preempt_disable_notrace();
	p = get_kprobe((kprobe_opcode_t *)ip);
	if (unlikely(!p) || kprobe_disabled(p))
		goto out;

	regs = ftrace_get_regs(fregs);
	kcb = get_kprobe_ctlblk();
	if (kprobe_running()) {
		kprobes_inc_nmissed_count(p);
	} else {
		unsigned long orig_ip = regs->csr_era;

		regs->csr_era = ip;

		__this_cpu_write(current_kprobe, p);
		kcb->kprobe_status = KPROBE_HIT_ACTIVE;
		if (!p->pre_handler || !p->pre_handler(p, regs)) {
			/*
			 * Emulate singlestep (and also recover regs->csr_era)
			 * as if there is a nop.
			 */
			regs->csr_era = (unsigned long)p->addr + LOONGARCH_INSN_SIZE;
			if (unlikely(p->post_handler)) {
				kcb->kprobe_status = KPROBE_HIT_SSDONE;
				p->post_handler(p, regs, 0);
			}
			regs->csr_era = orig_ip;
		}
		/*
		 * If pre_handler returns !0, it changes regs->ip. We have to
		 * skip emulating post_handler.
		 */
		__this_cpu_write(current_kprobe, NULL);
	}
out:
	preempt_enable_notrace();
	ftrace_test_recursion_unlock(bit);
}
NOKPROBE_SYMBOL(kprobe_ftrace_handler);

int arch_prepare_kprobe_ftrace(struct kprobe *p)
{
	p->ainsn.insn = NULL;
	return 0;
}
#endif /* CONFIG_KPROBES_ON_FTRACE */
