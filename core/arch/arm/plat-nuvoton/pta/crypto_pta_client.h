/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2020 Nuvoton Technology Corp. All rights reserved.
 */
#ifndef __CRYPTO_PTA_CLIENT_H
#define __CRYPTO_PTA_CLIENT_H

#define PTA_CRYPTO_UUID { 0x61d3c750, 0x9e72, 0x46b6, \
		{ 0x85, 0x7c, 0x46, 0xfa, 0x51, 0x27, 0x32, 0xac } }

#define TEE_ERROR_CRYPTO_BUSY		0x00000001
#define TEE_ERROR_CRYPTO_FAIL		0x00000002
#define TEE_ERROR_CRYPTO_INVALID	0x00000003
#define TEE_ERROR_CRYPTO_TIMEOUT	0x00000004
#define TEE_ERROR_CRYPTO_NOT_SUPPORT	0x00000005
#define TEE_ERROR_CRYPTO_ECC_VERIFY	0x00000011

/*
 * PTA_CMD_CRYPTO_INIT - Initialize Crypto Engine
 *
 * param[0] unused
 * param[1] unused
 * param[2] unused
 * param[3] unused
 *
 * Result:
 * TEE_SUCCESS - Invoke command success
 * TEE_ERROR_BAD_PARAMETERS - Incorrect input param
 * TEE_ERROR_CRYPTO_FAIL - Initialization failed
 */
#define PTA_CMD_CRYPTO_INIT		1

/*
 * PTA_CMD_CRYPTO_OPEN_SESSION - open a crypto session
 *
 * param[0] (in value)  - value.a: session class
 * param[1] (out value) - value.a: session ID
 * param[2] unused
 * param[3] unused
 *
 * Result:
 * TEE_SUCCESS - Invoke command success
 * TEE_ERROR_CRYPTO_INVALID - Invalid input param
 * TEE_ERROR_CRYPTO_FAIL - failed
 */
#define PTA_CMD_CRYPTO_OPEN_SESSION	2

/*
 * PTA_CMD_CRYPTO_CLOSE_SESSION - close an opened crypto session
 *
 * param[0] (in value)  - value.a: session class
 * param[1] (in value)  - value.a: session ID
 * param[2] unused
 * param[3] unused
 *
 * Result:
 * TEE_SUCCESS - Invoke command success
 * TEE_ERROR_CRYPTO_INVALID - Invalid input param
 * TEE_ERROR_CRYPTO_FAIL - failed
 */
#define PTA_CMD_CRYPTO_CLOSE_SESSION	3

/*
 * PTA_CMD_CRYPTO_AES_RUN - Run AES encrypt/decrypt
 *
 * param[0] (in value) - value.a: crypto session ID
 *                     - value.b: register AES_KSCTL
 * param[1] (inout memref) - memref.size: size of register map
 *                           memref.buffer: register map buffer
 * param[2] unused
 * param[3] unused
 *
 * Result:
 * TEE_SUCCESS - Invoke command success
 * TEE_ERROR_CRYPTO_INVALID - Invalid input param
 * TEE_ERROR_CRYPTO_FAIL - AES encrypt/decrypt operation failed
 */
#define PTA_CMD_CRYPTO_AES_RUN		5

/*
 * PTA_CMD_CRYPTO_SHA_START - Start a SHA session
 *
 * param[0] (in value) - value.a: session ID
 * param[1] (in value) - value.a: HMAC_CTL
 *                     - value.b: HMAC_KSCTL
 * param[2] (in value) - value.a: HMAC key length
 * param[3] unused
 *
 * Result:
 * TEE_SUCCESS - Invoke command success
 * TEE_ERROR_CRYPTO_INVALID - Invalid input param
 * TEE_ERROR_CRYPTO_FAIL - SHA operation failed
 */
#define PTA_CMD_CRYPTO_SHA_START	8

/*
 * PTA_CMD_CRYPTO_SHA_UPDATE - Update SHA input data
 *
 * param[0] (in value) - value.a: session ID
 *                     - value.b: digest byte length
 * param[1] (inout memref) - memref.size: size of register map
 *                           memref.buffer: register map buffer
 * param[2] unused
 * param[3] unused
 *
 * Result:
 * TEE_SUCCESS - Invoke command success
 * TEE_ERROR_CRYPTO_INVALID - Invalid input param
 * TEE_ERROR_CRYPTO_FAIL - SHA operation failed
 */
#define PTA_CMD_CRYPTO_SHA_UPDATE	9

/*
 * PTA_CMD_CRYPTO_SHA_FINAL - final update SHA input data and
 *                            get output digest
 *
 * param[0] (in value) - value.a: session ID
 *                     - value.b: digest byte length
 * param[1] (inout memref) - memref.size: size of register map
 *                           memref.buffer: register map buffer
 * param[2] unused
 * param[3] unused
 *
 * Result:
 * TEE_SUCCESS - Invoke command success
 * TEE_ERROR_CRYPTO_INVALID - Invalid input param
 * TEE_ERROR_CRYPTO_FAIL - SHA operation failed
 */
#define PTA_CMD_CRYPTO_SHA_FINAL	10

/*
 * PTA_CMD_CRYPTO_ECC_KEY_GEN - Run ECC public key generation
 *
 * param[0] (in value) - value.a: ECC curve ID
 * param[1] (inout memref) - memref.size: size of register map
 *                           memref.buffer: register map buffer
 * param[2] (in value) - value.a: shm offset of parameter block
 *                     - value.b: shm offset of output buffer
 * param[3] unused
 *
 * Result:
 * TEE_SUCCESS - Invoke command success
 * TEE_ERROR_CRYPTO_INVALID - Invalid input param
 * TEE_ERROR_CRYPTO_FAIL - ECC operation failed
 */
#define PTA_CMD_CRYPTO_ECC_KEY_GEN	13

/*
 * PTA_CMD_CRYPTO_ECC_PMUL - Run ECC point multiplication
 *
 * param[0] (in value) - value.a: ECC curve ID
 * param[1] (inout memref) - memref.size: size of register map
 *                           memref.buffer: register map buffer
 * param[2] (in value) - value.a: shm offset of parameter block
 *                     - value.b: shm offset of output buffer
 * param[3] unused
 *
 * Result:
 * TEE_SUCCESS - Invoke command success
 * TEE_ERROR_CRYPTO_INVALID - Invalid input param
 * TEE_ERROR_CRYPTO_FAIL - ECC operation failed
 */
#define PTA_CMD_CRYPTO_ECC_PMUL		15

/*
 * PTA_CMD_CRYPTO_ECC_SIG_VERIFY - Run ECC ECDSA signature verification
 *
 * param[0] (in value) - value.a: ECC curve ID
 * param[1] (inout memref) - memref.size: size of register map
 *                           memref.buffer: register map buffer
 * param[2] (in value) - value.a: shm offset of parameter block
 * param[3] unused
 *
 * Result:
 * TEE_SUCCESS - Invoke command success
 * TEE_ERROR_CRYPTO_INVALID - Invalid input param
 * TEE_ERROR_CRYPTO_FAIL - ECC operation failed
 * TEE_ERROR_CRYPTO_ECC_VERIFY - ECC ECDSA signature verification failed
 */
#define PTA_CMD_CRYPTO_ECC_SIG_VERIFY	16

/*
 * PTA_CMD_CRYPTO_ECC_SIG_GEN - Run ECC ECDSA signature generation
 *
 * param[0] (in value) - value.a: ECC curve ID
 * param[1] (inout memref) - memref.size: size of register map
 *                           memref.buffer: register map buffer
 * param[2] (in value) - value.a: shm offset of parameter block
 * param[3] unused
 *
 * Result:
 * TEE_SUCCESS - Invoke command success
 * TEE_ERROR_CRYPTO_INVALID - Invalid input param
 * TEE_ERROR_CRYPTO_FAIL - ECC operation failed
 */
#define PTA_CMD_CRYPTO_ECC_SIG_GEN	17

/*
 * PTA_CMD_CRYPTO_RSA_RUN - Run RSA engine
 *
 * param[0] unused
 * param[1] (inout memref) - memref.size: size of register map
 *                           memref.buffer: register map buffer
 * param[2] unused
 * param[3] unused
 *
 * Result:
 * TEE_SUCCESS - Invoke command success
 * TEE_ERROR_CRYPTO_INVALID - Invalid input param
 * TEE_ERROR_CRYPTO_FAIL - RSA operation failed
 */
#define PTA_CMD_CRYPTO_RSA_RUN		20

#endif /* __CRYPTO_PTA_CLIENT_H */
