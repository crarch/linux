/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2020 Loongson Technology Corporation Limited
 *
 * Author: Chong Qiao <qiaochong@loongson.cn>
 */

#include <linux/sched.h>

#include <asm/processor.h>
#include <asm/watch.h>
#include <asm/ptrace.h>
#include <linux/sched/task_stack.h>

unsigned long watch_csrrd(unsigned int reg)
{
	switch (reg) {
	case LOONGARCH_CSR_IB0ADDR + 8 * 0:
		return csr_readq(LOONGARCH_CSR_IB0ADDR + 8 * 0);
	case LOONGARCH_CSR_IB0ADDR + 8 * 1:
		return csr_readq(LOONGARCH_CSR_IB0ADDR + 8 * 1);
	case LOONGARCH_CSR_IB0ADDR + 8 * 2:
		return csr_readq(LOONGARCH_CSR_IB0ADDR + 8 * 2);
	case LOONGARCH_CSR_IB0ADDR + 8 * 3:
		return csr_readq(LOONGARCH_CSR_IB0ADDR + 8 * 3);
	case LOONGARCH_CSR_IB0ADDR + 8 * 4:
		return csr_readq(LOONGARCH_CSR_IB0ADDR + 8 * 4);
	case LOONGARCH_CSR_IB0ADDR + 8 * 5:
		return csr_readq(LOONGARCH_CSR_IB0ADDR + 8 * 5);
	case LOONGARCH_CSR_IB0ADDR + 8 * 6:
		return csr_readq(LOONGARCH_CSR_IB0ADDR + 8 * 6);
	case LOONGARCH_CSR_IB0ADDR + 8 * 7:
		return csr_readq(LOONGARCH_CSR_IB0ADDR + 8 * 7);

	case LOONGARCH_CSR_IB0MASK + 8 * 0:
		return csr_readq(LOONGARCH_CSR_IB0MASK + 8 * 0);
	case LOONGARCH_CSR_IB0MASK + 8 * 1:
		return csr_readq(LOONGARCH_CSR_IB0MASK + 8 * 1);
	case LOONGARCH_CSR_IB0MASK + 8 * 2:
		return csr_readq(LOONGARCH_CSR_IB0MASK + 8 * 2);
	case LOONGARCH_CSR_IB0MASK + 8 * 3:
		return csr_readq(LOONGARCH_CSR_IB0MASK + 8 * 3);
	case LOONGARCH_CSR_IB0MASK + 8 * 4:
		return csr_readq(LOONGARCH_CSR_IB0MASK + 8 * 4);
	case LOONGARCH_CSR_IB0MASK + 8 * 5:
		return csr_readq(LOONGARCH_CSR_IB0MASK + 8 * 5);
	case LOONGARCH_CSR_IB0MASK + 8 * 6:
		return csr_readq(LOONGARCH_CSR_IB0MASK + 8 * 6);
	case LOONGARCH_CSR_IB0MASK + 8 * 7:
		return csr_readq(LOONGARCH_CSR_IB0MASK + 8 * 7);

	case LOONGARCH_CSR_IB0ASID + 8 * 0:
		return csr_readq(LOONGARCH_CSR_IB0ASID + 8 * 0);
	case LOONGARCH_CSR_IB0ASID + 8 * 1:
		return csr_readq(LOONGARCH_CSR_IB0ASID + 8 * 1);
	case LOONGARCH_CSR_IB0ASID + 8 * 2:
		return csr_readq(LOONGARCH_CSR_IB0ASID + 8 * 2);
	case LOONGARCH_CSR_IB0ASID + 8 * 3:
		return csr_readq(LOONGARCH_CSR_IB0ASID + 8 * 3);
	case LOONGARCH_CSR_IB0ASID + 8 * 4:
		return csr_readq(LOONGARCH_CSR_IB0ASID + 8 * 4);
	case LOONGARCH_CSR_IB0ASID + 8 * 5:
		return csr_readq(LOONGARCH_CSR_IB0ASID + 8 * 5);
	case LOONGARCH_CSR_IB0ASID + 8 * 6:
		return csr_readq(LOONGARCH_CSR_IB0ASID + 8 * 6);
	case LOONGARCH_CSR_IB0ASID + 8 * 7:
		return csr_readq(LOONGARCH_CSR_IB0ASID + 8 * 7);

	case LOONGARCH_CSR_IB0CTL + 8 * 0:
		return csr_readq(LOONGARCH_CSR_IB0CTL + 8 * 0);
	case LOONGARCH_CSR_IB0CTL + 8 * 1:
		return csr_readq(LOONGARCH_CSR_IB0CTL + 8 * 1);
	case LOONGARCH_CSR_IB0CTL + 8 * 2:
		return csr_readq(LOONGARCH_CSR_IB0CTL + 8 * 2);
	case LOONGARCH_CSR_IB0CTL + 8 * 3:
		return csr_readq(LOONGARCH_CSR_IB0CTL + 8 * 3);
	case LOONGARCH_CSR_IB0CTL + 8 * 4:
		return csr_readq(LOONGARCH_CSR_IB0CTL + 8 * 4);
	case LOONGARCH_CSR_IB0CTL + 8 * 5:
		return csr_readq(LOONGARCH_CSR_IB0CTL + 8 * 5);
	case LOONGARCH_CSR_IB0CTL + 8 * 6:
		return csr_readq(LOONGARCH_CSR_IB0CTL + 8 * 6);
	case LOONGARCH_CSR_IB0CTL + 8 * 7:
		return csr_readq(LOONGARCH_CSR_IB0CTL + 8 * 7);

	case LOONGARCH_CSR_DB0ADDR + 8 * 0:
		return csr_readq(LOONGARCH_CSR_DB0ADDR + 8 * 0);
	case LOONGARCH_CSR_DB0ADDR + 8 * 1:
		return csr_readq(LOONGARCH_CSR_DB0ADDR + 8 * 1);
	case LOONGARCH_CSR_DB0ADDR + 8 * 2:
		return csr_readq(LOONGARCH_CSR_DB0ADDR + 8 * 2);
	case LOONGARCH_CSR_DB0ADDR + 8 * 3:
		return csr_readq(LOONGARCH_CSR_DB0ADDR + 8 * 3);
	case LOONGARCH_CSR_DB0ADDR + 8 * 4:
		return csr_readq(LOONGARCH_CSR_DB0ADDR + 8 * 4);
	case LOONGARCH_CSR_DB0ADDR + 8 * 5:
		return csr_readq(LOONGARCH_CSR_DB0ADDR + 8 * 5);
	case LOONGARCH_CSR_DB0ADDR + 8 * 6:
		return csr_readq(LOONGARCH_CSR_DB0ADDR + 8 * 6);
	case LOONGARCH_CSR_DB0ADDR + 8 * 7:
		return csr_readq(LOONGARCH_CSR_DB0ADDR + 8 * 7);

	case LOONGARCH_CSR_DB0MASK + 8 * 0:
		return csr_readq(LOONGARCH_CSR_DB0MASK + 8 * 0);
	case LOONGARCH_CSR_DB0MASK + 8 * 1:
		return csr_readq(LOONGARCH_CSR_DB0MASK + 8 * 1);
	case LOONGARCH_CSR_DB0MASK + 8 * 2:
		return csr_readq(LOONGARCH_CSR_DB0MASK + 8 * 2);
	case LOONGARCH_CSR_DB0MASK + 8 * 3:
		return csr_readq(LOONGARCH_CSR_DB0MASK + 8 * 3);
	case LOONGARCH_CSR_DB0MASK + 8 * 4:
		return csr_readq(LOONGARCH_CSR_DB0MASK + 8 * 4);
	case LOONGARCH_CSR_DB0MASK + 8 * 5:
		return csr_readq(LOONGARCH_CSR_DB0MASK + 8 * 5);
	case LOONGARCH_CSR_DB0MASK + 8 * 6:
		return csr_readq(LOONGARCH_CSR_DB0MASK + 8 * 6);
	case LOONGARCH_CSR_DB0MASK + 8 * 7:
		return csr_readq(LOONGARCH_CSR_DB0MASK + 8 * 7);

	case LOONGARCH_CSR_DB0ASID + 8 * 0:
		return csr_readq(LOONGARCH_CSR_DB0ASID + 8 * 0);
	case LOONGARCH_CSR_DB0ASID + 8 * 1:
		return csr_readq(LOONGARCH_CSR_DB0ASID + 8 * 1);
	case LOONGARCH_CSR_DB0ASID + 8 * 2:
		return csr_readq(LOONGARCH_CSR_DB0ASID + 8 * 2);
	case LOONGARCH_CSR_DB0ASID + 8 * 3:
		return csr_readq(LOONGARCH_CSR_DB0ASID + 8 * 3);
	case LOONGARCH_CSR_DB0ASID + 8 * 4:
		return csr_readq(LOONGARCH_CSR_DB0ASID + 8 * 4);
	case LOONGARCH_CSR_DB0ASID + 8 * 5:
		return csr_readq(LOONGARCH_CSR_DB0ASID + 8 * 5);
	case LOONGARCH_CSR_DB0ASID + 8 * 6:
		return csr_readq(LOONGARCH_CSR_DB0ASID + 8 * 6);
	case LOONGARCH_CSR_DB0ASID + 8 * 7:
		return csr_readq(LOONGARCH_CSR_DB0ASID + 8 * 7);

	case LOONGARCH_CSR_DB0CTL + 8 * 0:
		return csr_readq(LOONGARCH_CSR_DB0CTL + 8 * 0);
	case LOONGARCH_CSR_DB0CTL + 8 * 1:
		return csr_readq(LOONGARCH_CSR_DB0CTL + 8 * 1);
	case LOONGARCH_CSR_DB0CTL + 8 * 2:
		return csr_readq(LOONGARCH_CSR_DB0CTL + 8 * 2);
	case LOONGARCH_CSR_DB0CTL + 8 * 3:
		return csr_readq(LOONGARCH_CSR_DB0CTL + 8 * 3);
	case LOONGARCH_CSR_DB0CTL + 8 * 4:
		return csr_readq(LOONGARCH_CSR_DB0CTL + 8 * 4);
	case LOONGARCH_CSR_DB0CTL + 8 * 5:
		return csr_readq(LOONGARCH_CSR_DB0CTL + 8 * 5);
	case LOONGARCH_CSR_DB0CTL + 8 * 6:
		return csr_readq(LOONGARCH_CSR_DB0CTL + 8 * 6);
	case LOONGARCH_CSR_DB0CTL + 8 * 7:
		return csr_readq(LOONGARCH_CSR_DB0CTL + 8 * 7);

	case LOONGARCH_CSR_FWPS:
		return csr_readq(LOONGARCH_CSR_FWPS);
	case LOONGARCH_CSR_MWPS:
		return csr_readq(LOONGARCH_CSR_MWPS);
	case LOONGARCH_CSR_FWPC:
		return csr_readq(LOONGARCH_CSR_FWPC);
	case LOONGARCH_CSR_MWPC:
		return csr_readq(LOONGARCH_CSR_MWPC);
	default:
		printk("read watch register number error %d\n", reg);
	}
	return 0;
}
EXPORT_SYMBOL(watch_csrrd);

void watch_csrwr(unsigned long val, unsigned int reg)
{
	switch (reg) {
	case LOONGARCH_CSR_IB0ADDR + 8 * 0:
		csr_writeq(val, LOONGARCH_CSR_IB0ADDR + 8 * 0);
		break;
	case LOONGARCH_CSR_IB0ADDR + 8 * 1:
		csr_writeq(val, LOONGARCH_CSR_IB0ADDR + 8 * 1);
		break;
	case LOONGARCH_CSR_IB0ADDR + 8 * 2:
		csr_writeq(val, LOONGARCH_CSR_IB0ADDR + 8 * 2);
		break;
	case LOONGARCH_CSR_IB0ADDR + 8 * 3:
		csr_writeq(val, LOONGARCH_CSR_IB0ADDR + 8 * 3);
		break;
	case LOONGARCH_CSR_IB0ADDR + 8 * 4:
		csr_writeq(val, LOONGARCH_CSR_IB0ADDR + 8 * 4);
		break;
	case LOONGARCH_CSR_IB0ADDR + 8 * 5:
		csr_writeq(val, LOONGARCH_CSR_IB0ADDR + 8 * 5);
		break;
	case LOONGARCH_CSR_IB0ADDR + 8 * 6:
		csr_writeq(val, LOONGARCH_CSR_IB0ADDR + 8 * 6);
		break;
	case LOONGARCH_CSR_IB0ADDR + 8 * 7:
		csr_writeq(val, LOONGARCH_CSR_IB0ADDR + 8 * 7);
		break;

	case LOONGARCH_CSR_IB0MASK + 8 * 0:
		csr_writeq(val, LOONGARCH_CSR_IB0MASK + 8 * 0);
		break;
	case LOONGARCH_CSR_IB0MASK + 8 * 1:
		csr_writeq(val, LOONGARCH_CSR_IB0MASK + 8 * 1);
		break;
	case LOONGARCH_CSR_IB0MASK + 8 * 2:
		csr_writeq(val, LOONGARCH_CSR_IB0MASK + 8 * 2);
		break;
	case LOONGARCH_CSR_IB0MASK + 8 * 3:
		csr_writeq(val, LOONGARCH_CSR_IB0MASK + 8 * 3);
		break;
	case LOONGARCH_CSR_IB0MASK + 8 * 4:
		csr_writeq(val, LOONGARCH_CSR_IB0MASK + 8 * 4);
		break;
	case LOONGARCH_CSR_IB0MASK + 8 * 5:
		csr_writeq(val, LOONGARCH_CSR_IB0MASK + 8 * 5);
		break;
	case LOONGARCH_CSR_IB0MASK + 8 * 6:
		csr_writeq(val, LOONGARCH_CSR_IB0MASK + 8 * 6);
		break;
	case LOONGARCH_CSR_IB0MASK + 8 * 7:
		csr_writeq(val, LOONGARCH_CSR_IB0MASK + 8 * 7);
		break;

	case LOONGARCH_CSR_IB0ASID + 8 * 0:
		csr_writeq(val, LOONGARCH_CSR_IB0ASID + 8 * 0);
		break;
	case LOONGARCH_CSR_IB0ASID + 8 * 1:
		csr_writeq(val, LOONGARCH_CSR_IB0ASID + 8 * 1);
		break;
	case LOONGARCH_CSR_IB0ASID + 8 * 2:
		csr_writeq(val, LOONGARCH_CSR_IB0ASID + 8 * 2);
		break;
	case LOONGARCH_CSR_IB0ASID + 8 * 3:
		csr_writeq(val, LOONGARCH_CSR_IB0ASID + 8 * 3);
		break;
	case LOONGARCH_CSR_IB0ASID + 8 * 4:
		csr_writeq(val, LOONGARCH_CSR_IB0ASID + 8 * 4);
		break;
	case LOONGARCH_CSR_IB0ASID + 8 * 5:
		csr_writeq(val, LOONGARCH_CSR_IB0ASID + 8 * 5);
		break;
	case LOONGARCH_CSR_IB0ASID + 8 * 6:
		csr_writeq(val, LOONGARCH_CSR_IB0ASID + 8 * 6);
		break;
	case LOONGARCH_CSR_IB0ASID + 8 * 7:
		csr_writeq(val, LOONGARCH_CSR_IB0ASID + 8 * 7);
		break;

	case LOONGARCH_CSR_IB0CTL + 8 * 0:
		csr_writeq(val, LOONGARCH_CSR_IB0CTL + 8 * 0);
		break;
	case LOONGARCH_CSR_IB0CTL + 8 * 1:
		csr_writeq(val, LOONGARCH_CSR_IB0CTL + 8 * 1);
		break;
	case LOONGARCH_CSR_IB0CTL + 8 * 2:
		csr_writeq(val, LOONGARCH_CSR_IB0CTL + 8 * 2);
		break;
	case LOONGARCH_CSR_IB0CTL + 8 * 3:
		csr_writeq(val, LOONGARCH_CSR_IB0CTL + 8 * 3);
		break;
	case LOONGARCH_CSR_IB0CTL + 8 * 4:
		csr_writeq(val, LOONGARCH_CSR_IB0CTL + 8 * 4);
		break;
	case LOONGARCH_CSR_IB0CTL + 8 * 5:
		csr_writeq(val, LOONGARCH_CSR_IB0CTL + 8 * 5);
		break;
	case LOONGARCH_CSR_IB0CTL + 8 * 6:
		csr_writeq(val, LOONGARCH_CSR_IB0CTL + 8 * 6);
		break;
	case LOONGARCH_CSR_IB0CTL + 8 * 7:
		csr_writeq(val, LOONGARCH_CSR_IB0CTL + 8 * 7);
		break;

	case LOONGARCH_CSR_DB0ADDR + 8 * 0:
		csr_writeq(val, LOONGARCH_CSR_DB0ADDR + 8 * 0);
		break;
	case LOONGARCH_CSR_DB0ADDR + 8 * 1:
		csr_writeq(val, LOONGARCH_CSR_DB0ADDR + 8 * 1);
		break;
	case LOONGARCH_CSR_DB0ADDR + 8 * 2:
		csr_writeq(val, LOONGARCH_CSR_DB0ADDR + 8 * 2);
		break;
	case LOONGARCH_CSR_DB0ADDR + 8 * 3:
		csr_writeq(val, LOONGARCH_CSR_DB0ADDR + 8 * 3);
		break;
	case LOONGARCH_CSR_DB0ADDR + 8 * 4:
		csr_writeq(val, LOONGARCH_CSR_DB0ADDR + 8 * 4);
		break;
	case LOONGARCH_CSR_DB0ADDR + 8 * 5:
		csr_writeq(val, LOONGARCH_CSR_DB0ADDR + 8 * 5);
		break;
	case LOONGARCH_CSR_DB0ADDR + 8 * 6:
		csr_writeq(val, LOONGARCH_CSR_DB0ADDR + 8 * 6);
		break;
	case LOONGARCH_CSR_DB0ADDR + 8 * 7:
		csr_writeq(val, LOONGARCH_CSR_DB0ADDR + 8 * 7);
		break;

	case LOONGARCH_CSR_DB0MASK + 8 * 0:
		csr_writeq(val, LOONGARCH_CSR_DB0MASK + 8 * 0);
		break;
	case LOONGARCH_CSR_DB0MASK + 8 * 1:
		csr_writeq(val, LOONGARCH_CSR_DB0MASK + 8 * 1);
		break;
	case LOONGARCH_CSR_DB0MASK + 8 * 2:
		csr_writeq(val, LOONGARCH_CSR_DB0MASK + 8 * 2);
		break;
	case LOONGARCH_CSR_DB0MASK + 8 * 3:
		csr_writeq(val, LOONGARCH_CSR_DB0MASK + 8 * 3);
		break;
	case LOONGARCH_CSR_DB0MASK + 8 * 4:
		csr_writeq(val, LOONGARCH_CSR_DB0MASK + 8 * 4);
		break;
	case LOONGARCH_CSR_DB0MASK + 8 * 5:
		csr_writeq(val, LOONGARCH_CSR_DB0MASK + 8 * 5);
		break;
	case LOONGARCH_CSR_DB0MASK + 8 * 6:
		csr_writeq(val, LOONGARCH_CSR_DB0MASK + 8 * 6);
		break;
	case LOONGARCH_CSR_DB0MASK + 8 * 7:
		csr_writeq(val, LOONGARCH_CSR_DB0MASK + 8 * 7);
		break;

	case LOONGARCH_CSR_DB0ASID + 8 * 0:
		csr_writeq(val, LOONGARCH_CSR_DB0ASID + 8 * 0);
		break;
	case LOONGARCH_CSR_DB0ASID + 8 * 1:
		csr_writeq(val, LOONGARCH_CSR_DB0ASID + 8 * 1);
		break;
	case LOONGARCH_CSR_DB0ASID + 8 * 2:
		csr_writeq(val, LOONGARCH_CSR_DB0ASID + 8 * 2);
		break;
	case LOONGARCH_CSR_DB0ASID + 8 * 3:
		csr_writeq(val, LOONGARCH_CSR_DB0ASID + 8 * 3);
		break;
	case LOONGARCH_CSR_DB0ASID + 8 * 4:
		csr_writeq(val, LOONGARCH_CSR_DB0ASID + 8 * 4);
		break;
	case LOONGARCH_CSR_DB0ASID + 8 * 5:
		csr_writeq(val, LOONGARCH_CSR_DB0ASID + 8 * 5);
		break;
	case LOONGARCH_CSR_DB0ASID + 8 * 6:
		csr_writeq(val, LOONGARCH_CSR_DB0ASID + 8 * 6);
		break;
	case LOONGARCH_CSR_DB0ASID + 8 * 7:
		csr_writeq(val, LOONGARCH_CSR_DB0ASID + 8 * 7);
		break;

	case LOONGARCH_CSR_DB0CTL + 8 * 0:
		csr_writeq(val, LOONGARCH_CSR_DB0CTL + 8 * 0);
		break;
	case LOONGARCH_CSR_DB0CTL + 8 * 1:
		csr_writeq(val, LOONGARCH_CSR_DB0CTL + 8 * 1);
		break;
	case LOONGARCH_CSR_DB0CTL + 8 * 2:
		csr_writeq(val, LOONGARCH_CSR_DB0CTL + 8 * 2);
		break;
	case LOONGARCH_CSR_DB0CTL + 8 * 3:
		csr_writeq(val, LOONGARCH_CSR_DB0CTL + 8 * 3);
		break;
	case LOONGARCH_CSR_DB0CTL + 8 * 4:
		csr_writeq(val, LOONGARCH_CSR_DB0CTL + 8 * 4);
		break;
	case LOONGARCH_CSR_DB0CTL + 8 * 5:
		csr_writeq(val, LOONGARCH_CSR_DB0CTL + 8 * 5);
		break;
	case LOONGARCH_CSR_DB0CTL + 8 * 6:
		csr_writeq(val, LOONGARCH_CSR_DB0CTL + 8 * 6);
		break;
	case LOONGARCH_CSR_DB0CTL + 8 * 7:
		csr_writeq(val, LOONGARCH_CSR_DB0CTL + 8 * 7);
		break;

	case LOONGARCH_CSR_FWPS:
		csr_writeq(val, LOONGARCH_CSR_FWPS);
		break;
	case LOONGARCH_CSR_MWPS:
		csr_writeq(val, LOONGARCH_CSR_MWPS);
		break;
	default:
		printk("write watch register number error %d\n", reg);
	}
}
EXPORT_SYMBOL(watch_csrwr);

/*
 * Install the watch registers for the current thread.	A maximum of
 * four registers are installed although the machine may have more.
 */
void loongarch_install_watch_registers(struct task_struct *t)
{
	int i, j, dbcn;
	struct loongarch3264_watch_reg_state *watches = &t->thread.watch.loongarch3264;

	dbcn = boot_cpu_data.watch_dreg_count;
	for (i = 0; i < current_cpu_data.watch_reg_use_cnt; i++) {
		if (watches->irw[i] & (LA_WATCH_R | LA_WATCH_W)) {
			unsigned int dbc = 0x1e;

			if ((watches->irw[i] & LA_WATCH_R))
				dbc |= 1<<8;
			if ((watches->irw[i] & LA_WATCH_W))
				dbc |= 1<<9;

			watch_csrwr(watches->addr[i], LOONGARCH_CSR_DB0ADDR + 8*i);
			watch_csrwr(watches->mask[i], LOONGARCH_CSR_DB0MASK + 8*i);
			watch_csrwr(0, LOONGARCH_CSR_DB0ASID + 8*i);
			watch_csrwr(dbc, LOONGARCH_CSR_DB0CTL + 8*i);

		} else if (watches->irw[i] & LA_WATCH_I) {
			j = i - dbcn;
			watch_csrwr(watches->addr[i], LOONGARCH_CSR_IB0ADDR + 8*j);
			watch_csrwr(watches->mask[i], LOONGARCH_CSR_IB0MASK + 8*j);
			watch_csrwr(0, LOONGARCH_CSR_IB0ASID + 8*j);
			watch_csrwr(0x1e, LOONGARCH_CSR_IB0CTL + 8*j);
			if ((task_pt_regs(t)->csr_era & ~watches->mask[i]) ==
					(watches->addr[i] & ~watches->mask[i]))
				watch_csrwr(0x10000, LOONGARCH_CSR_FWPS);
		} else if (watches->irwmask[i]) {
			if (i < dbcn) {
				watch_csrwr(0x0, LOONGARCH_CSR_DB0CTL + 8*i);
			} else {
				j = i - dbcn;
				watch_csrwr(0x0, LOONGARCH_CSR_IB0CTL + 8*j);
			}
		}
	}
}
EXPORT_SYMBOL(loongarch_install_watch_registers);

#define PRMD_WE (1UL<<3) /* PRMD watch enable, restore to CRMD when eret */

void loongarch_clear_prev_watch_registers(struct task_struct *prev)
{
	struct pt_regs *regs = task_pt_regs(prev);

	loongarch_clear_watch_registers();
	prev->thread.csr_prmd &= ~PRMD_WE;
	regs->csr_prmd &= ~PRMD_WE;
}

void loongarch_install_next_watch_registers(struct task_struct *next)
{
	struct pt_regs *regs = task_pt_regs(next);

	loongarch_install_watch_registers(next);
	next->thread.csr_prmd |= PRMD_WE;
	regs->csr_prmd |= PRMD_WE;
}

#define CTRL_WE 1 /* Breakpoint can only be written by hw debugger */

void loongarch_update_watch_registers(struct task_struct *t)
{
	struct loongarch3264_watch_reg_state *watches =
		&t->thread.watch.loongarch3264;
	int i, j, dbcn, ctl;

	dbcn = boot_cpu_data.watch_dreg_count;
	for (i = 0; i < current_cpu_data.watch_reg_use_cnt; i++) {
		if (i < dbcn) {
			ctl = watch_csrrd(LOONGARCH_CSR_DB0CTL + 8*i);
			if (ctl & CTRL_WE)
				watches->irwmask[i] = 0;
			else
				watches->irwmask[i] = LA_WATCH_R | LA_WATCH_W;
		} else {
			j = i - dbcn;
			ctl = watch_csrrd(LOONGARCH_CSR_IB0CTL + 8*j);
			if (ctl & CTRL_WE)
				watches->irwmask[i] = 0;
			else
				watches->irwmask[i] = LA_WATCH_I;
		}
	}
}
/*
 * Read back the watchhi registers so the user space debugger has
 * access to the I, R, and W bits.  A maximum of four registers are
 * read although the machine may have more.
 */

void loongarch_read_watch_registers(struct pt_regs *regs)
{
	struct loongarch3264_watch_reg_state *watches =
		&current->thread.watch.loongarch3264;
	unsigned int i, j, dbcn, ibst, dbst;

	dbcn = boot_cpu_data.watch_dreg_count;
	ibst = watch_csrrd(LOONGARCH_CSR_FWPS);
	dbst = watch_csrrd(LOONGARCH_CSR_MWPS);

	for (i = 0; i < current_cpu_data.watch_reg_use_cnt; i++) {
		if (i < dbcn) {
			watches->addr[i] = watch_csrrd(LOONGARCH_CSR_DB0ADDR + 8*i);
			watches->mask[i] = watch_csrrd(LOONGARCH_CSR_DB0MASK + 8*i);
			if (dbst & (1u << i)) {
				int dbc = watch_csrrd(LOONGARCH_CSR_DB0CTL + i*8);

				watches->irwstat[i] = 0;
				if (dbc & (1<<8))
					watches->irwstat[i] |= LA_WATCH_R;
				if (dbc & (1<<9))
					watches->irwstat[i] |= LA_WATCH_W;
			}
		} else {
			j = i - dbcn;
			watches->addr[i] = watch_csrrd(LOONGARCH_CSR_IB0ADDR + 8*j);
			watches->mask[i] = watch_csrrd(LOONGARCH_CSR_IB0MASK + 8*j);
			watches->irwstat[i] = 0;
			if (ibst & (1u << j))
				watches->irwstat[i] |= LA_WATCH_I;
		}
	}

	if (ibst & 0xffff)
		watch_csrwr(ibst, LOONGARCH_CSR_FWPS);
	if (dbst & 0xffff)
		watch_csrwr(dbst, LOONGARCH_CSR_MWPS);
}

/*
 * Disable all watch registers. Although only four registers are
 * installed, all are cleared to eliminate the possibility of endless
 * looping in the watch handler.
 */
void loongarch_clear_watch_registers(void)
{
	unsigned int i, j, dbcn, ibst, dbst;

	ibst = watch_csrrd(LOONGARCH_CSR_FWPS);
	dbst = watch_csrrd(LOONGARCH_CSR_MWPS);
	dbcn = boot_cpu_data.watch_dreg_count;

	/*
	 *  bit 16: skip next event
	 *  bit 0-15: breakpoint triggered, W1C
	 */

	if (ibst & 0x1ffff)
		watch_csrwr(ibst&~0x10000, LOONGARCH_CSR_FWPS);
	if (dbst & 0x1ffff)
		watch_csrwr(dbst&~0x10000, LOONGARCH_CSR_MWPS);

	for (i = 0; i < current_cpu_data.watch_reg_use_cnt; i++) {
		if (i < dbcn) {
			watch_csrwr(0, LOONGARCH_CSR_DB0ADDR + 8*i);
			watch_csrwr(0, LOONGARCH_CSR_DB0MASK + 8*i);
			watch_csrwr(0, LOONGARCH_CSR_DB0ASID + 8*i);
			watch_csrwr(0, LOONGARCH_CSR_DB0CTL + 8*i);
		} else {
			j = i - dbcn;
			watch_csrwr(0, LOONGARCH_CSR_IB0ADDR + 8*j);
			watch_csrwr(0, LOONGARCH_CSR_IB0MASK + 8*j);
			watch_csrwr(0, LOONGARCH_CSR_IB0ASID + 8*j);
			watch_csrwr(0, LOONGARCH_CSR_IB0CTL + 8*j);
		}
	}
}
EXPORT_SYMBOL(loongarch_clear_watch_registers);

void loongarch_probe_watch_registers(struct cpuinfo_loongarch *c)
{
	unsigned int ibcn, dbcn, total;

	ibcn = watch_csrrd(LOONGARCH_CSR_FWPC) & 0x3f;
	dbcn = watch_csrrd(LOONGARCH_CSR_MWPC) & 0x3f;
	c->watch_dreg_count = dbcn;
	c->watch_ireg_count = ibcn;
	total =  ibcn + dbcn;
	c->watch_reg_use_cnt = (total < NUM_WATCH_REGS) ? total : NUM_WATCH_REGS;
}
