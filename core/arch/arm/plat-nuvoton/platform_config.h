/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015, Linaro Limited
 * Copyright (C) 2020, Nuvoton Technology Corporation
 */

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#include <mm/generic_ram_layout.h>

/* Make stacks aligned to data cache line length */
#define STACK_ALIGNMENT		64

#ifdef ARM64
#ifdef CFG_WITH_PAGER
#error "Pager not supported for ARM64"
#endif
#endif /*ARM64*/

#if defined(PLATFORM_FLAVOR_MA35D1) || defined(PLATFORM_FLAVOR_MA35D0) || defined(PLATFORM_FLAVOR_MA35H0)

#define GIC_BASE		0x50801000UL
#define GICC_OFFSET		0x2000
#define GICD_OFFSET		0x1000

#define CRYPTO_BASE		0x40300000UL
#define CRYPTO_REG_SIZE		0x1000

#define KS_BASE			0x40340000UL
#define KS_REG_SIZE		0x1000

#define OTP_BASE		0x40350000UL
#define OTP_REG_SIZE		0x1000

#define TSI_BASE		0x40360000UL
#define TSI_REG_SIZE		0x1000

#define SYS_BASE		0x40460000UL
#define SYS_REG_SIZE		0x1000

#define UART0_BASE		0x40700000UL
#define UART0_REG_SIZE		0x1000

#define TRNG_BASE		0x40B90000UL
#define TRNG_REG_SIZE		0x1000

#define WHC1_BASE		0x503B0000UL
#define WHC1_REG_SIZE		0x1000

#define CONSOLE_UART_BASE	UART0_BASE
#define CONSOLE_BAUDRATE	115200
#define CONSOLE_UART_CLK_IN_HZ	24000000

#define DRAM0_BASE		0x80000000
#define DRAM0_SIZE		0x40000000

#define SYS_CHIPCFG		0x1F4
#define TSIEN			(0x1 << 8)

#else
#error "Unknown platform flavor"
#endif

#ifdef CFG_WITH_LPAE
#define MAX_XLAT_TABLES		5
#endif

#endif /*PLATFORM_CONFIG_H*/
