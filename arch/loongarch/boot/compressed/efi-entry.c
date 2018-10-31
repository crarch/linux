// SPDX-License-Identifier: GPL-2.0
#include <linux/efi.h>
#include <asm/efi.h>
#include <asm/sections.h>
#include <asm/loongarchregs.h>
#include <asm/mach-loongson64/boot_param.h>

typedef void (*kernel_entry_t)(int argc, char *argv[], struct boot_params *boot_p);

unsigned char efi_heap[BOOT_HEAP_SIZE];
kernel_entry_t kernel_entry = (kernel_entry_t)KERNEL_ENTRY;
efi_status_t __efiapi efi_pe_entry(efi_handle_t handle, efi_system_table_t *sys_table);

efi_status_t start(efi_handle_t handle, efi_system_table_t *sys_table)
{
	/* Config Direct Mapping */
	csr_writeq(CSR_DMW0_INIT, LOONGARCH_CSR_DMWIN0);
	csr_writeq(CSR_DMW1_INIT, LOONGARCH_CSR_DMWIN1);

	/* Clear BSS */
	memset(_edata, 0, _end - _edata);

	return efi_pe_entry(handle, sys_table);
}
