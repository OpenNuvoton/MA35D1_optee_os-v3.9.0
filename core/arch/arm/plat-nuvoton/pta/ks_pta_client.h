// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020 Nuvoton Technology Corp. All rights reserved.
 */
#ifndef __KS_PTA_CLIENT_H
#define __KS_PTA_CLIENT_H

#define PTA_KS_UUID { 0xaac83d50, 0xc303, 0x41ee, \
		{ 0xb8, 0xf2, 0x70, 0x6c, 0x0b, 0x78, 0xe5, 0xad } }

#define TEE_ERROR_KS_BUSY		0x00000001
#define TEE_ERROR_KS_FAIL		0x00000002
#define TEE_ERROR_KS_INVALID		0x00000003
#define TEE_ERROR_OTP_INVALID		0x00000011
#define TEE_ERROR_OTP_FAIL		0x00000012

/*
 * PTA_CMD_KS_INIT - Initialize Key Store
 *
 * param[0] unused
 * param[1] unused
 * param[2] unused
 * param[3] unused
 *
 * Result:
 * TEE_SUCCESS - Invoke command success
 * TEE_ERROR_BAD_PARAMETERS - Incorrect input param
 * TEE_ERROR_KS_FAIL - Initialization failed
 */
#define PTA_CMD_KS_INIT			0x1

/*
 * PTA_CMD_KS_READ - Read a Key Store key
 *
 * param[0] (in value) - value.a: 0: SRAM; 2: OTP
 *                       value.b: key number
 * param[1] (inout memref) - memref.size: word count of the key
 *                           memref.buffer: key buffer
 * param[2] unused
 * param[3] unused
 *
 * Result:
 * TEE_SUCCESS - Invoke command success
 * TEE_ERROR_KS_INVALID - Incorrect input param
 * TEE_ERROR_KS_FAIL - Read operation failed
 */
#define PTA_CMD_KS_READ			0x2

/*
 * PTA_CMD_KS_WRITE - Write a Key Store key
 *
 * param[0] (in value) - value.a: 0: SRAM; 2: OTP
 *                       value.b: meta data
 * param[1] (inout memref) - memref.size: word count of the key
 *                           memref.buffer: key buffer
 * param[2] (out value) - value.a: key number
 * param[3] unused
 *
 * Result:
 * TEE_SUCCESS - Invoke command success
 * TEE_ERROR_KS_INVALID - Invalid parameter
 * TEE_ERROR_KS_FAIL - Write operation failed
 */
#define PTA_CMD_KS_WRITE		0x3

/*
 * PTA_CMD_KS_ERASE - Erase a Key Store key
 *
 * param[0] (in value) - value.a: 0: SRAM; 2: OTP
 *                       value.b: key number
 * param[1] unused
 * param[2] unused
 * param[3] unused
 *
 * Result:
 * TEE_SUCCESS - Invoke command success
 * TEE_ERROR_KS_INVALID - Incorrect input param
 * TEE_ERROR_KS_FAIL - Erase operation failed
 */
#define PTA_CMD_KS_ERASE		0x4

/*
 * PTA_CMD_KS_ERASE_ALL - Erase all Key Store SRAM keys
 *
 * param[0] unused
 * param[1] unused
 * param[2] unused
 * param[3] unused
 *
 * Result:
 * TEE_SUCCESS - Invoke command success
 * TEE_ERROR_KS_FAIL - Erase all operation failed
 */
#define PTA_CMD_KS_ERASE_ALL		0x5

/*
 * PTA_CMD_KS_REVOKE - Revoke a Key Store key
 *
 * param[0] (in value) - value.a: 0: SRAM; 2: OTP
 *                       value.b: key number
 * param[1] unused
 * param[2] unused
 * param[3] unused
 *
 * Result:
 * TEE_SUCCESS - Invoke command success
 * TEE_ERROR_KS_INVALID - Incorrect input param
 * TEE_ERROR_KS_FAIL - Revoke operation failed
 */
#define PTA_CMD_KS_REVOKE		0x6

/*
 * PTA_CMD_KS_REMAIN - Get the remaining size of Key Store SRAM
 *
 * param[0] (out value) - value.a: remaining size of SRAM
 * param[1] unused
 * param[2] unused
 * param[3] unused
 *
 * Result:
 * TEE_SUCCESS - Invoke command success
 * TEE_ERROR_KS_FAIL - Get remain operation failed
 */
#define PTA_CMD_KS_REMAIN		0x7

/*
 * PTA_CMD_OTP_READ - Read OTP
 *
 * param[0] (in value) - value.a: OTP address
 * param[1] (inout memref) - memref.size: word count of OTP key
 *                           memref.buffer: key buffer
 * param[2] unused
 * param[3] unused
 *
 * Result:
 * TEE_SUCCESS - Invoke command success
 * TEE_ERROR_OTP_INVALID - Incorrect input param
 * TEE_ERROR_OTP_FAIL - read OTP failed
 */
#define PTA_CMD_OTP_READ		0x12

#endif /* __KS_PTA_CLIENT_H */
