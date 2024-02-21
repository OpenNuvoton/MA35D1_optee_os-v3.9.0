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
#include <kernel/tee_common_otp.h>
#include <mm/core_memprot.h>
#include <tee/cache.h>
#include <platform_config.h>
#include <stdint.h>
#include <tee/entry_std.h>
#include <tee/entry_fast.h>
#include <io.h>
#include <tsi_cmd.h>

#if defined(PLATFORM_FLAVOR_MA35D1)
#define LOAD_TSI_PATCH
#endif

register_phys_mem_pgdir(MEM_AREA_IO_NSEC, UART0_BASE, UART0_REG_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, SYS_BASE, SYS_REG_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, TRNG_BASE, TRNG_REG_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, KS_BASE, KS_REG_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, OTP_BASE, OTP_REG_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, CRYPTO_BASE, CRYPTO_REG_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, TSI_BASE, TSI_REG_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, WHC1_BASE, WHC1_REG_SIZE);

#ifdef LOAD_TSI_PATCH
#include "tsi_patch.c"
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

#if defined(PLATFORM_FLAVOR_MA35D1)
int ma35d1_tsi_init(void)
{
	vaddr_t sys_base = core_mmu_get_va(SYS_BASE, MEM_AREA_IO_SEC);
	int  ret;

	if (!(io_read32(sys_base + SYS_CHIPCFG) & TSIEN)) {
		/*
		 * TSI enabled. Invoke TSI command and return here.
		 */
		uint32_t  version_code;

		/* enable WHC1 clock */
		io_write32(sys_base + 0x208, io_read32(sys_base + 0x208) | (1 << 5));

		ret = TSI_Get_Version(&version_code);
		if (ret != ST_SUCCESS) {
			/* TSI is not ready. Init TSI. */
			while (1) {
				ret = TSI_Get_Version(&version_code);
				if (ret == ST_SUCCESS) {
					EMSG("TSI F/W version: %x\n", version_code);
					break;
				}
				if (ret == ST_WAIT_TSI_SYNC) {
					EMSG("Wait TSI_Sync.\n");
					TSI_Sync();
				}
			}
		}
	}

#ifdef LOAD_TSI_PATCH
	ret = TSI_Load_Image((uint32_t)virt_to_phys(tsi_patch_image), sizeof(tsi_patch_image));
	if (ret == 0)
		EMSG("Load TSI image successful.\n");
	else
		EMSG("Load TSI image failed!! %d\n", ret);
#endif
	return 0;
}

__aligned(64) static unsigned int huk_key_buff[4] = { 0x35d1, 0x980, 0x970, 0x00 };

TEE_Result tee_otp_get_hw_unique_key(struct tee_hw_unique_key *hwkey)
{
	uint32_t *huk_key = (uint32_t *)virt_to_phys(huk_key_buff);
	TEE_Result ret;

	ret = ma35d1_tsi_init();
	if (ret != 0)
		return TEE_ERROR_GENERIC;

	cache_operation(TEE_CACHEINVALIDATE, huk_key_buff, sizeof(huk_key_buff));

	ret = TSI_KS_Read(0x2, 0, huk_key, 4);
	if (ret != ST_SUCCESS) {
		 EMSG("%s - OTP UID does not exist, possibly not burned. Default key will be used instead.\n", __func__);
	}

	memcpy(&hwkey->data[0], &huk_key[0], sizeof(hwkey->data));

	return TEE_SUCCESS;
}
#endif
