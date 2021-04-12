/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2020 Loongson Technology Co., Ltd.
 */
#include <linux/init.h>
#include <linux/threads.h>

#include <asm/addrspace.h>
#include <asm/asm.h>
#include <asm/asmmacro.h>
#include <asm/regdef.h>
#include <asm/loongarchregs.h>
#include <asm/stackframe.h>

SYM_ENTRY(_stext, SYM_L_GLOBAL, SYM_A_NONE)

	__REF

SYM_CODE_START(kernel_entry)			# kernel entry point

	/* Config direct window and set PG */
	li.d		t0, CSR_DMW0_INIT	# UC, PLV0, 0x8000 xxxx xxxx xxxx
	csrwr		t0, LOONGARCH_CSR_DMWIN0
	li.d		t0, CSR_DMW1_INIT	# CA, PLV0, 0x9000 xxxx xxxx xxxx
	csrwr		t0, LOONGARCH_CSR_DMWIN1
	/* Enable PG */
	li.w		t0, 0xb0		# PLV=0, IE=0, PG=1
	csrwr		t0, LOONGARCH_CSR_CRMD
	li.w		t0, 0x04		# PLV=0, PIE=1, PWE=0
	csrwr		t0, LOONGARCH_CSR_PRMD
	li.w		t0, 0x00		# FPE=0, SXE=0, ASXE=0, BTE=0
	csrwr		t0, LOONGARCH_CSR_EUEN

	/* We might not get launched at the address the kernel is linked to,
	   so we jump there.  */
	la.abs		t0, 0f
	jirl		zero, t0, 0
0:
#ifdef CONFIG_USE_OF

	li.d		t1, -2
	or		t2, a1, zero
	beq		a0, t1, dtb_found

	li.d		t2, 0
dtb_found:
#endif
	la		t0, __bss_start		# clear .bss
	st.d		zero, t0, 0
	la		t1, __bss_stop - LONGSIZE
1:
	addi.d		t0, t0, LONGSIZE
	st.d		zero, t0, 0
	bne		t0, t1, 1b

	la		t0, fw_arg0
	st.d		a0, t0, 0		# firmware arguments
	la		t0, fw_arg1
	st.d		a1, t0, 0
	la		t0, fw_arg2
	st.d		a2, t0, 0
	la		t0, fw_arg3
	st.d		a3, t0, 0

#ifdef CONFIG_USE_OF
	la		t0, fw_passed_dtb
	st.d		t2, t0, 0
#endif

	/* KScratch3 used for percpu base, initialized as 0 */
	csrwr		zero, PERCPU_BASE_KS
	/* GPR21 used for percpu base (runtime), initialized as 0 */
	or		u0, zero, zero

	la		tp, init_thread_union
	/* Set the SP after an empty pt_regs.  */
	PTR_LI		sp, (_THREAD_SIZE - 32 - PT_SIZE)
	PTR_ADDU	sp, sp, tp
	set_saved_sp	sp, t0, t1
	PTR_ADDIU	sp, sp, -4 * SZREG	# init stack pointer

#ifdef CONFIG_RELOCATABLE
	/* Copy kernel and apply the relocations */
	bl		relocate_kernel

	/* Repoint the sp into the new kernel image */
	PTR_LI		sp, (_THREAD_SIZE - 32 - PT_SIZE)
	PTR_ADDU	sp, sp, tp
	set_saved_sp	sp, t0, t1
	PTR_ADDIU	sp, sp, -4 * SZREG	# init stack pointer

	/*
	 * relocate_kernel returns the entry point either
	 * in the relocated kernel or the original if for
	 * some reason relocation failed.
	 */
	jirl		zero, v0, 0
#else
	bl		start_kernel
#endif

SYM_CODE_END(kernel_entry)

#ifdef CONFIG_SMP

/*
 * SMP slave cpus entry point.	Board specific code for bootstrap calls this
 * function after setting up the stack and tp registers.
 */
SYM_CODE_START(smpboot_entry)
	li.d		t0, CSR_DMW0_INIT	# UC, PLV0
	csrwr		t0, LOONGARCH_CSR_DMWIN0
	li.d		t0, CSR_DMW1_INIT	# CA, PLV0
	csrwr		t0, LOONGARCH_CSR_DMWIN1
	li.w		t0, 0xb0		# PLV=0, IE=0, PG=1
	csrwr		t0, LOONGARCH_CSR_CRMD
	li.w		t0, 0x04		# PLV=0, PIE=1, PWE=0
	csrwr		t0, LOONGARCH_CSR_PRMD
	li.w		t0, 0x00		# FPE=0, SXE=0, ASXE=0, BTE=0
	csrwr		t0, LOONGARCH_CSR_EUEN

	la.abs		t0, cpuboot_data
	ld.d		sp, t0, CPU_BOOT_STACK
	ld.d		tp, t0, CPU_BOOT_TINFO

	la.abs	t0, 0f
	jirl	zero, t0, 0
0:
	bl		start_secondary
SYM_CODE_END(smpboot_entry)

#endif /* CONFIG_SMP */

SYM_ENTRY(kernel_entry_end, SYM_L_GLOBAL, SYM_A_NONE)
