// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2015, Linaro Limited
 * Copyright (C) 2020, Nuvoton Technology Corporation
 */

#include <console.h>
#include <drivers/nuvoton_uart.h>
#include <kernel/boot.h>
#include <kernel/panic.h>
#include <kernel/pm_stubs.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <stdint.h>
#include <tee/entry_std.h>
#include <tee/entry_fast.h>
#include <io.h>
#include <tsi_cmd.h>

//#define LOAD_TSI_PATCH

register_phys_mem_pgdir(MEM_AREA_IO_NSEC, UART0_BASE, UART0_REG_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, SYS_BASE, SYS_REG_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, TRNG_BASE, TRNG_REG_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, KS_BASE, KS_REG_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, CRYPTO_BASE, CRYPTO_REG_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, TSI_BASE, TSI_REG_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, WHC1_BASE, WHC1_REG_SIZE);

#ifdef LOAD_TSI_PATCH
static uint8_t _tsi_patch[] = {
#include "TSI_Patch_secure.dat"
};
#endif

static const struct thread_handlers handlers = {
	.cpu_on = cpu_on_handler,
	.cpu_off = pm_do_nothing,
	.cpu_suspend = pm_do_nothing,
	.cpu_resume = pm_do_nothing,
	.system_off = pm_do_nothing,
	.system_reset = pm_do_nothing,
};

static struct nuvoton_uart_data console_data;


const struct thread_handlers *boot_get_handlers(void)
{
	return &handlers;
}

void console_init(void)
{
	nuvoton_uart_init(&console_data, CONSOLE_UART_BASE);
	register_serial_console(&console_data.chip);
}

int ma35d1_tsi_init(void)
{
	vaddr_t sys_base = core_mmu_get_va(SYS_BASE, MEM_AREA_IO_SEC);
	int  ret;

	if (io_read32(sys_base + SYS_CHIPCFG) & TSIEN) {
		/*
		 * TSI enabled. Invoke TSI command and return here.
		 */
		uint32_t  version_code;

		/* enable WHC1 clock */
		io_write32(sys_base + 0x208,
			   io_read32(sys_base + 0x208) | (1 << 5));

		while (1) {
			ret = TSI_Get_Version(&version_code);
			if (ret == ST_SUCCESS) {
				EMSG("TSI FW version: %x\n", version_code);
				break;
			}
			if (ret == ST_WAIT_TSI_SYNC) {
				EMSG("Do TSI_Sync.\n");
				TSI_Sync();
			}
		}

#ifdef LOAD_TSI_PATCH
		if (TSI_Load_Image((uint32_t)virt_to_phys(_tsi_patch),
				   sizeof(_tsi_patch)) == 0)
			EMSG("Load TSI image successful.\n");
		else
			EMSG("Load TSI image failed!!\n");
#endif
	}
	return 0;
}
