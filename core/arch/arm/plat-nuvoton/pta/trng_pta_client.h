// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020 Nuvoton Technology Corp. All rights reserved.
 */

#ifndef __TRNG_PTA_CLIENT_H
#define __TRNG_PTA_CLIENT_H

#define PTA_TRNG_UUID { 0x9f831ffa, 0x1823, 0x4ee9, \
		{ 0x8f, 0xb2, 0x41, 0x57, 0x1f, 0x64, 0x32, 0xe1 } }

#define TEE_ERROR_TRNG_BUSY		0x00000001
#define TEE_ERROR_TRNG_GEN_NOISE	0x00000002
#define TEE_ERROR_TRNG_COMMAND		0x00000003
#define TEE_ERROR_TRNG_FAILED		0x00000004

/*
 * PTA_CMD_TRNG_INIT - Initialize TRNG hardware
 *
 * param[0] (out value) - value.a: TRNG STAT register
 *                        value.b: TRNG ISTAT register
 * param[1] unused
 * param[2] unused
 * param[3] unused
 *
 * Result:
 * TEE_SUCCESS - Invoke command success
 * TEE_ERROR_TRNG_BUSY - TRNG hardware busy
 * TEE_ERROR_TRNG_GEN_NOISE - Failed to generate noise or nounce
 * TEE_ERROR_TRNG_COMMAND - TRNG command failed
 */
#define PTA_CMD_TRNG_INIT		0x1

/*
 * PTA_CMD_TRNG_READ - Get TRNG data
 *
 * param[0] (inout memref) - TRNG data buffer memory reference
 * param[1] unused
 * param[2] unused
 * param[3] unused
 *
 * Result:
 * TEE_SUCCESS - Invoke command success
 * TEE_ERROR_BAD_PARAMETERS - Incorrect input param
 */
#define PTA_CMD_TRNG_READ		0x2

#endif /* __TRNG_PTA_CLIENT_H */
