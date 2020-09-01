// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016, Spreadtrum Communications Inc.
 * Copyright (c) 2017, Linaro Limited
 * Copyright (C) 2020, Nuvoton Technology Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include <drivers/nuvoton_uart.h>
#include <io.h>
#include <keep.h>
#include <util.h>

/* Register definitions */
#define REG_RBR     (0x00)  /*!< Receive Buffer Register */
#define REG_THR     (0x00)  /*!< Transmit Holding Register */
#define REG_FSR     (0x18)  /*!< FIFO Status Register */

#define TX_FULL     (0x1<<23)
#define TX_EMPTY    (0x1<<22)
#define RX_FULL     (0x1<<15)
#define RX_EMPTY    (0x1<<14)

static vaddr_t chip_to_base(struct serial_chip *chip)
{
	struct nuvoton_uart_data *pd =
		container_of(chip, struct nuvoton_uart_data, chip);

	return io_pa_or_va(&pd->base);
}

static void nuvoton_uart_flush(struct serial_chip *chip)
{
	vaddr_t base = chip_to_base(chip);

	while (!(io_read32(base + REG_FSR) & TX_EMPTY))
		;
}

static bool nuvoton_uart_have_rx_data(struct serial_chip *chip)
{
	vaddr_t base = chip_to_base(chip);

	return !(io_read32(base + REG_FSR) & RX_EMPTY);
}

static void nuvoton_uart_putc(struct serial_chip *chip, int ch)
{
	vaddr_t base = chip_to_base(chip);

	nuvoton_uart_flush(chip);
	io_write32(base + REG_THR, ch);
}

static int nuvoton_uart_getchar(struct serial_chip *chip)
{
	vaddr_t base = chip_to_base(chip);

	while (!nuvoton_uart_have_rx_data(chip))
		;

	return io_read32(base + REG_RBR) & 0xff;
}

static const struct serial_ops nuvoton_uart_ops = {
	.flush = nuvoton_uart_flush,
	.getchar = nuvoton_uart_getchar,
	.have_rx_data = nuvoton_uart_have_rx_data,
	.putc = nuvoton_uart_putc,
};
// KEEP_PAGER(nuvoton_uart_ops);

void nuvoton_uart_init(struct nuvoton_uart_data *pd, paddr_t base)
{
	pd->base.pa = base;
	pd->chip.ops = &nuvoton_uart_ops;
}
