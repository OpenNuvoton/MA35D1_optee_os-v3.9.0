// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020 Nuvoton Technology Corp. All rights reserved.
 *
 */
#include <crypto/crypto.h>
#include <kernel/delay.h>
#include <kernel/pseudo_ta.h>
#include <kernel/spinlock.h>
#include <kernel/timer.h>
#include <kernel/tee_time.h>
#include <mm/core_memprot.h>
#include <tee/cache.h>
#include <platform_config.h>
#include <tsi_cmd.h>
#include <io.h>
#include <string.h>
#include <crypto_pta.h>
#include <crypto_pta_client.h>

#define PTA_NAME "nvt_crypto.pta"

#define RSA_BUSY_TIMEOUT    2000

#define nu_write_reg(reg, val)	io_write32(crypto_base + (reg), (val))
#define nu_read_reg(reg)	io_read32(crypto_base + (reg))

__aligned(32) static uint32_t  param_block[16];

static bool is_timeout(TEE_Time *t_start, uint32_t timeout)
{
	TEE_Time  t_now;
	uint32_t  time_elapsed;

	tee_time_get_sys_time(&t_now);
	time_elapsed = (t_now.seconds - t_start->seconds) * 1000 +
		    (int)t_now.millis - (int)t_start->millis;

	if (time_elapsed > timeout)
		return true;
	return false;
}

static TEE_Result ma35d1_crypto_init(void)
{
	vaddr_t sys_base = core_mmu_get_va(SYS_BASE, MEM_AREA_IO_SEC);
	vaddr_t tsi_base = core_mmu_get_va(TSI_BASE, MEM_AREA_IO_SEC);

	if (io_read32(sys_base + SYS_CHIPCFG) & TSIEN)
		return ma35d1_tsi_init();

	if ((io_read32(tsi_base + 0x210) & 0x7) != 0x2) {
		do {
			io_write32(tsi_base + 0x100, 0x59);
			io_write32(tsi_base + 0x100, 0x16);
			io_write32(tsi_base + 0x100, 0x88);
		} while (io_read32(tsi_base + 0x100) == 0UL);

		io_write32(tsi_base + 0x240, TSI_PLL_SETTING);

		/* wait PLL stable */
		while ((io_read32(tsi_base + 0x250) & 0x4) == 0)
			;

		/* Select TSI HCLK from PLL */
		io_write32(tsi_base + 0x210, (io_read32(tsi_base +
			   0x210) & ~0x7) | 0x2);
	}

	/* enable Crypto engine clock */
	io_write32(tsi_base + 0x204, io_read32(tsi_base + 0x204) | (1 << 12));
	return TEE_SUCCESS;
}

static TEE_Result tsi_open_session(uint32_t types,
				   TEE_Param params[TEE_NUM_PARAMS])
{
	int   sid;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
				     TEE_PARAM_TYPE_VALUE_OUTPUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE)) {
		EMSG("bad parameters types: 0x%" PRIx32, types);
		return TEE_ERROR_BAD_PARAMETERS;
	}
	if (TSI_Open_Session(params[0].value.a, &sid) != ST_SUCCESS)
		return TEE_ERROR_CRYPTO_FAIL;

	params[1].value.a = sid;
	return TEE_SUCCESS;
}

static TEE_Result tsi_close_session(uint32_t types,
				    TEE_Param params[TEE_NUM_PARAMS])
{
	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
				     TEE_PARAM_TYPE_VALUE_INPUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE)) {
		EMSG("bad parameters types: 0x%" PRIx32, types);
		return TEE_ERROR_BAD_PARAMETERS;
	}
	if (TSI_Close_Session(params[0].value.a,
			      params[1].value.a) != ST_SUCCESS)
		return TEE_ERROR_CRYPTO_FAIL;

	return TEE_SUCCESS;
}

static TEE_Result tsi_aes_run(uint32_t types,
			      TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t  *reg_map;
	uint32_t  reg_map_pa;    /* physical address of reg_map */
	uint32_t  aes_ctl, aes_ksctl, sid, opmode;
	int       keysz;
	bool      is_gcm;
	int       ret;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
				     TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE)) {
		EMSG("bad parameters types: 0x%" PRIx32, types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	reg_map = params[1].memref.buffer;
	reg_map_pa = (uint32_t)virt_to_phys(reg_map);

	sid = params[0].value.a;
	aes_ctl = reg_map[AES_CTL / 4];
	aes_ksctl = params[0].value.b;
	opmode = (aes_ctl & AES_CTL_OPMODE_MASK) >> AES_CTL_OPMODE_OFFSET;
	keysz = (aes_ctl & AES_CTL_KEYSZ_MASK) >> AES_CTL_KEYSZ_OFFSET;

	if (opmode == AES_MODE_GCM || opmode == AES_MODE_CCM) {
		is_gcm = true;
		param_block[0] = reg_map[AES_GCM_IVCNT(0) / 4];
		param_block[1] = reg_map[AES_GCM_ACNT(0) / 4];
		param_block[2] = reg_map[AES_GCM_PCNT(0) / 4];
		param_block[3] = reg_map[AES_SADDR / 4];
		param_block[4] = reg_map[AES_DADDR / 4];
	} else {
		is_gcm = false;
	}

	cache_operation(TEE_CACHEFLUSH,
			(void *)((uint64_t)reg_map + AES_IV(0)), 16);

	if (TSI_AES_Set_IV(sid, reg_map_pa + AES_IV(0)) != ST_SUCCESS)
		return TEE_ERROR_CRYPTO_FAIL;

	cache_operation(TEE_CACHEFLUSH,
			(void *)((uint64_t)reg_map + AES_KEY(0)), 32);

	if (TSI_AES_Set_Key(sid, keysz, reg_map_pa + AES_KEY(0)) != ST_SUCCESS)
		return TEE_ERROR_CRYPTO_FAIL;

	/* TSI use FDBCK DMA, force swap here */
	aes_ctl |= AES_CTL_KINSWAP | AES_CTL_KOUTSWAP;

	ret = TSI_AES_Set_Mode(sid,                           /* sid      */
			(aes_ctl & AES_CTL_KINSWAP) ? 1 : 0,  /* kinswap  */
			(aes_ctl & AES_CTL_KOUTSWAP) ? 1 : 0, /* kinswap  */
			(aes_ctl & AES_CTL_INSWAP) ? 1 : 0,   /* inswap   */
			(aes_ctl & AES_CTL_OUTSWAP) ? 1 : 0,  /* outswap  */
			(aes_ctl & AES_CTL_SM4EN) ? 1 : 0,    /* sm4en    */
			(aes_ctl & AES_CTL_ENCRPT) ? 1 : 0,   /* encrypt  */
			opmode,                               /* mode     */
			keysz,                                /* keysz    */
			(aes_ksctl & AES_KSCTL_RSSRC_MASK) >>
				AES_KSCTL_RSSRC_OFFSET,       /* ks       */
			(aes_ksctl & AES_KSCTL_NUM_MASK) >>
				AES_KSCTL_NUM_OFFSET          /* ksnum    */
			);
	if (ret != ST_SUCCESS)
		return TEE_ERROR_CRYPTO_FAIL;

	if (is_gcm) {
		int  flush_len;

		flush_len = reg_map[AES_CNT / 4] +
			    reg_map[AES_GCM_IVCNT(0) / 4] +
			    reg_map[AES_GCM_ACNT(0) / 4] +
			    reg_map[AES_GCM_PCNT(0) / 4];

		cache_operation(TEE_CACHEFLUSH,
				(void *)((uint64_t)reg_map[AES_SADDR / 4]),
				flush_len);
		cache_operation(TEE_CACHEINVALIDATE,
				(void *)((uint64_t)reg_map[AES_DADDR / 4]),
				flush_len);
		cache_operation(TEE_CACHEFLUSH,
				(void *)((uint64_t)param_block), 32);

		ret = TSI_AES_GCM_Run(sid,
				      aes_ctl & AES_CTL_DMALAST ? 1 : 0,
				      reg_map[AES_CNT / 4],
				      (uint32_t)virt_to_phys(param_block));
	} else {
		cache_operation(TEE_CACHEFLUSH,
				(void *)((uint64_t)reg_map[AES_SADDR / 4]),
				reg_map[AES_CNT / 4]);
		cache_operation(TEE_CACHEINVALIDATE,
				(void *)((uint64_t)reg_map[AES_DADDR / 4]),
				reg_map[AES_CNT / 4]);
		ret = TSI_AES_Run(sid,
				  aes_ctl & AES_CTL_DMALAST ? 1 : 0,
				  reg_map[AES_CNT / 4], reg_map[AES_SADDR / 4],
				  reg_map[AES_DADDR / 4]);
	}

	if (ret != ST_SUCCESS)
		return TEE_ERROR_CRYPTO_FAIL;

	ret = TSI_Access_Feedback(sid, 1, 4, reg_map_pa + AES_FDBCK(0));
	EMSG("TSI_Access_Feedback ret = %d\n", ret);

	cache_operation(TEE_CACHEINVALIDATE,
			(void *)((uint64_t)reg_map + AES_FDBCK(0)), 32);

	EMSG("SWAP FDBCK: %08x %08x %08x %08x\n", reg_map[AES_FDBCK(0) / 4],
	     reg_map[AES_FDBCK(1) / 4], reg_map[AES_FDBCK(2) / 4],
	     reg_map[AES_FDBCK(3) / 4]);

	return TEE_SUCCESS;
}

static TEE_Result ma35d1_aes_run(uint32_t types,
				  TEE_Param params[TEE_NUM_PARAMS])
{
	vaddr_t   crypto_base = core_mmu_get_va(CRYPTO_BASE, MEM_AREA_IO_SEC);
	uint32_t  *reg_map;
	uint32_t  i;
	TEE_Time  t_start;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
				     TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE)) {
		EMSG("bad parameters types: 0x%" PRIx32, types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	reg_map = params[1].memref.buffer;

	tee_time_get_sys_time(&t_start);
	while ((nu_read_reg(AES_STS) & AES_STS_BUSY) ||
	       (nu_read_reg(INTSTS) & (INTSTS_AESIF | INTSTS_AESEIF))) {
		if (is_timeout(&t_start, 500) == true)
			return TEE_ERROR_CRYPTO_BUSY;
	}

	nu_write_reg(AES_CTL, 0);
	nu_write_reg(INTEN, nu_read_reg(INTEN) | (INTEN_AESIEN |
					INTEN_AESEIEN));
	nu_write_reg(INTSTS, (INTSTS_AESIF | INTSTS_AESEIF));

	nu_write_reg(AES_KSCTL, params[0].value.b);

	nu_write_reg(AES_GCM_IVCNT(0), reg_map[AES_GCM_IVCNT(0) / 4]);
	nu_write_reg(AES_GCM_IVCNT(1), 0);
	nu_write_reg(AES_GCM_ACNT(0), reg_map[AES_GCM_ACNT(0) / 4]);
	nu_write_reg(AES_GCM_ACNT(1), 0);
	nu_write_reg(AES_GCM_PCNT(0), reg_map[AES_GCM_PCNT(0) / 4]);
	nu_write_reg(AES_GCM_PCNT(1), 0);

	for (i = 0; i < 8; i++)
		nu_write_reg(AES_KEY(i), reg_map[AES_KEY(i) / 4]);

	for (i = 0; i < 4; i++)
		nu_write_reg(AES_IV(i), reg_map[AES_IV(i) / 4]);

	nu_write_reg(AES_SADDR, reg_map[AES_SADDR / 4]);
	nu_write_reg(AES_DADDR, reg_map[AES_DADDR / 4]);
	nu_write_reg(AES_CNT, reg_map[AES_CNT / 4]);

	nu_write_reg(AES_CTL, reg_map[AES_CTL / 4]);

	tee_time_get_sys_time(&t_start);
	while ((nu_read_reg(AES_STS) & AES_STS_BUSY) ||
	       !(nu_read_reg(INTSTS) & (INTSTS_AESIF | INTSTS_AESEIF))) {
		if (is_timeout(&t_start, 500) == true)
			return TEE_ERROR_CRYPTO_TIMEOUT;
	}

	nu_write_reg(INTSTS, (INTSTS_AESIF | INTSTS_AESEIF));

	for (i = 0; i < 4; i++)
		reg_map[AES_FDBCK(i) / 4] = nu_read_reg(AES_FDBCK(i));

	return TEE_SUCCESS;
}

static TEE_Result tsi_sha_start(uint32_t types,
				TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t  hmac_ctl;
	uint32_t  hmac_ksctl;
	int       keylen, ret;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
				     TEE_PARAM_TYPE_VALUE_INPUT,
				     TEE_PARAM_TYPE_VALUE_INPUT,
				     TEE_PARAM_TYPE_NONE)) {
		EMSG("bad parameters types: 0x%" PRIx32, types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	hmac_ctl = params[1].value.a;
	hmac_ksctl = params[1].value.b;
	if (hmac_ctl & HMAC_CTL_HMACEN)
		keylen = params[2].value.a;
	else
		keylen = 0;
EMSG("hmac_ctl = 0x%x\n", hmac_ctl);
	ret = TSI_SHA_Start(params[0].value.a,                  /* sid      */
			(hmac_ctl & HMAC_CTL_INSWAP) ? 1 : 0,   /* inswap   */
			(hmac_ctl & HMAC_CTL_OUTSWAP) ? 1 : 0,  /* outswap  */
			(hmac_ctl & SHA_MODE_SEL_MASK) >>
					SHA_MODE_SEL_OFFSET,    /* mode_sel */
			(hmac_ctl & HMAC_CTL_HMACEN) ? 1 : 0,   /* hmac     */
			(hmac_ctl & HMAC_CTL_OPMODE_MASK) >>
					HMAC_CTL_OPMODE_OFFSET, /* mode     */
			keylen,                                 /* keylen   */
			(hmac_ksctl >> 5) & 0x7,                /* ks       */
			hmac_ksctl & 0x1f                       /* ks_num   */
			);
	if (ret != ST_SUCCESS)
		return TEE_ERROR_CRYPTO_FAIL;

	return TEE_SUCCESS;
}

static TEE_Result tsi_sha_update(uint32_t types,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t  *reg_map;
	uint32_t  ret;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
				     TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE)) {
		EMSG("bad parameters types: 0x%" PRIx32, types);
		return TEE_ERROR_BAD_PARAMETERS;
	}
	reg_map = params[1].memref.buffer;

	cache_operation(TEE_CACHEFLUSH,
			(void *)((uint64_t)reg_map[HMAC_SADDR / 4]),
			reg_map[HMAC_DMACNT / 4]);

	ret = TSI_SHA_Update(params[0].value.a,      /* sid      */
			reg_map[HMAC_DMACNT / 4],    /* data_cnt */
			reg_map[HMAC_SADDR / 4]      /* src_addr */
			);
	if (ret != ST_SUCCESS)
		return TEE_ERROR_CRYPTO_FAIL;

	return TEE_SUCCESS;
}

static TEE_Result tsi_sha_final(uint32_t types,
				TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t  *reg_map;
	uint32_t  reg_map_pa;
	int       ret;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
				     TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE)) {
		EMSG("bad parameters types: 0x%" PRIx32, types);
		return TEE_ERROR_BAD_PARAMETERS;
	}
	reg_map = params[1].memref.buffer;
	reg_map_pa = (uint32_t)virt_to_phys(reg_map);

	cache_operation(TEE_CACHEINVALIDATE,
			(void *)((uint64_t)reg_map + HMAC_DGST(0)),
			0x100);
	cache_operation(TEE_CACHEFLUSH,
			(void *)((uint64_t)reg_map[HMAC_SADDR / 4]),
			reg_map[HMAC_DMACNT / 4]);

	ret = TSI_SHA_Finish(params[0].value.a,      /* sid       */
			params[0].value.b / 4,       /* wcnt      */
			reg_map[HMAC_DMACNT / 4],    /* data_cnt  */
			reg_map[HMAC_SADDR / 4],     /* src_addr  */
			reg_map_pa + HMAC_DGST(0)    /* dest_addr */
			);
	if (ret != ST_SUCCESS)
		return TEE_ERROR_CRYPTO_FAIL;

	return TEE_SUCCESS;
}

static TEE_Result ma35d1_sha_update(uint32_t types,
				     TEE_Param params[TEE_NUM_PARAMS])
{
	vaddr_t   crypto_base = core_mmu_get_va(CRYPTO_BASE, MEM_AREA_IO_SEC);
	uint32_t  *reg_map;
	uint32_t  i;
	TEE_Time  t_start;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
				     TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE)) {
		EMSG("bad parameters types: 0x%" PRIx32, types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	reg_map = params[1].memref.buffer;

	tee_time_get_sys_time(&t_start);
	while (nu_read_reg(HMAC_STS) & HMAC_STS_BUSY) {
		if (is_timeout(&t_start, 500) == true)
			return TEE_ERROR_CRYPTO_BUSY;
	}

	nu_write_reg(INTEN, nu_read_reg(INTEN) | (INTEN_HMACIEN |
					INTEN_HMACEIEN));
	nu_write_reg(INTSTS, (INTSTS_HMACIF | INTSTS_HMACEIF));

	nu_write_reg(HMAC_KSCTL, reg_map[HMAC_KSCTL / 4]);
	nu_write_reg(HMAC_KEYCNT, reg_map[HMAC_KEYCNT / 4]);
	nu_write_reg(HMAC_SADDR, reg_map[HMAC_SADDR / 4]);
	nu_write_reg(HMAC_DMACNT, reg_map[HMAC_DMACNT / 4]);
	nu_write_reg(HMAC_FBADDR, reg_map[HMAC_FBADDR / 4]);

	nu_write_reg(HMAC_CTL, reg_map[HMAC_CTL / 4]);

	tee_time_get_sys_time(&t_start);
	while ((nu_read_reg(HMAC_STS) & HMAC_STS_BUSY) ||
	       !(nu_read_reg(INTSTS) & (INTSTS_HMACIF | INTSTS_HMACEIF))) {
		if (is_timeout(&t_start, 500) == true)
			return TEE_ERROR_CRYPTO_BUSY;
	}
	nu_write_reg(INTSTS, (INTSTS_HMACIF | INTSTS_HMACEIF));

	if (reg_map[HMAC_CTL / 4] & HMAC_CTL_DMALAST) {
		for (i = 0; i < 16; i++)
			reg_map[HMAC_DGST(i) / 4] = nu_read_reg(HMAC_DGST(i));
	}
	return TEE_SUCCESS;
}

static char  ch2hex(char ch)
{
	if (ch <= '9')
		ch = ch - '0';
	else if ((ch <= 'z') && (ch >= 'a'))
		ch = ch - 'a' + 10U;
	else
		ch = ch - 'A' + 10U;
	return ch;
}

static void Hex2Reg(char input[], uint32_t reg[])
{
	char      hex;
	int       si, ri;
	uint32_t  i, val32;

	si = (int)strlen(input) - 1;
	ri = 0;

	while (si >= 0) {
		val32 = 0UL;
		for (i = 0UL; (i < 8UL) && (si >= 0); i++) {
			hex = ch2hex(input[si]);
			val32 |= (uint32_t)hex << (i * 4UL);
			si--;
		}
		reg[ri++] = val32;
	}
}

static TEE_Result tsi_ecc_pmul(uint32_t types,
			       TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t  *reg_map;
	uint32_t  reg_map_pa;
	uint32_t  ecc_ksctl, ecc_ksxy;
	int       rssrc, msel, sps;
	int       ret;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
				     TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_VALUE_INPUT,
				     TEE_PARAM_TYPE_NONE)) {
		EMSG("bad parameters types: 0x%" PRIx32, types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	reg_map = params[1].memref.buffer;
	reg_map_pa = (uint32_t)virt_to_phys(reg_map);

	ecc_ksctl = reg_map[ECC_KSCTL / 4];
	ecc_ksxy = reg_map[ECC_KSXY / 4];
		reg_map_pa = (uint32_t)virt_to_phys(reg_map);

	rssrc = (ecc_ksctl & ECC_KSCTL_RSSRCK_MASK) >> ECC_KSCTL_RSSRCK_OFFSET;
	if (rssrc == 0)
		msel = 2;
	else if (rssrc == 2)
		msel = 1;
	else
		msel = 3;

	sps = (ecc_ksxy & ECC_KSXY_RSSRCX_MASK) >> ECC_KSXY_RSSRCX_OFFSET;
	if (sps == 0)
		sps = 2;
	else if (rssrc == 2)
		sps = 1;
	else
		sps = 3;

	cache_operation(TEE_CACHEFLUSH, (void *)((uint64_t)reg_map +
				params[2].value.a), 1728);
	cache_operation(TEE_CACHEINVALIDATE, (void *)((uint64_t)reg_map +
				params[2].value.a), 1152);

	ret = TSI_ECC_Multiply(params[0].value.a,             /* curve_id   */
			(ecc_ksctl & ECC_KSCTL_ECDH) ? 1 : 0, /* type       */
			msel,                                 /* msel       */
			sps,                                  /* sps        */
			(ecc_ksctl & ECC_KSCTL_NUMK_MASK) >>
				ECC_KSCTL_NUMK_OFFSET,        /* m_knum     */
			(ecc_ksxy & ECC_KSXY_NUMX_MASK) >>
				ECC_KSXY_NUMX_OFFSET,         /* x_knum     */
			(ecc_ksxy & ECC_KSXY_NUMY_MASK) >>
				ECC_KSXY_NUMY_OFFSET,         /* y_knum     */
			reg_map_pa + params[2].value.a,       /* param_addr */
			reg_map_pa + params[2].value.b        /* dest_addr  */
			);
	if (ret != ST_SUCCESS)
		return TEE_ERROR_CRYPTO_FAIL;

	Hex2Reg((char *)((uint64_t)params[0].value.b),
		(uint32_t *)((uint64_t)reg_map + ECC_X1(0)));
	Hex2Reg((char *)((uint64_t)params[0].value.b + 0x240),
		(uint32_t *)((uint64_t)reg_map + ECC_X1(0)));

	return TEE_SUCCESS;
}

static TEE_Result ma35d1_ecc_pmul(uint32_t types,
				   TEE_Param params[TEE_NUM_PARAMS])
{
	vaddr_t   crypto_base = core_mmu_get_va(CRYPTO_BASE, MEM_AREA_IO_SEC);
	uint32_t  *reg_map;
	uint32_t  i;
	TEE_Time  t_start;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
				     TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_VALUE_INPUT,
				     TEE_PARAM_TYPE_NONE)) {
		EMSG("bad parameters types: 0x%" PRIx32, types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	reg_map = params[1].memref.buffer;

	tee_time_get_sys_time(&t_start);
	while ((nu_read_reg(ECC_STS) & ECC_STS_BUSY) ||
	       (nu_read_reg(INTSTS) & (INTSTS_ECCIF | INTSTS_ECCEIF))) {
		if (is_timeout(&t_start, 500) == true)
			return TEE_ERROR_CRYPTO_BUSY;
	}

	nu_write_reg(ECC_CTL, 0);
	nu_write_reg(INTEN, nu_read_reg(INTEN) | (INTEN_ECCIEN |
					INTEN_ECCEIEN));
	nu_write_reg(INTSTS, (INTSTS_ECCIF | INTSTS_ECCEIF));

	nu_write_reg(ECC_KSCTL, reg_map[ECC_KSCTL / 4]);
	nu_write_reg(ECC_KSXY, reg_map[ECC_KSXY / 4]);

	for (i = 0; i < ECC_KEY_WCNT; i++)
		nu_write_reg(ECC_X1(i), reg_map[ECC_X1(i) / 4]);

	for (i = 0; i < ECC_KEY_WCNT; i++)
		nu_write_reg(ECC_Y1(i), reg_map[ECC_Y1(i) / 4]);

	for (i = 0; i < ECC_KEY_WCNT; i++)
		nu_write_reg(ECC_X2(i), reg_map[ECC_X2(i) / 4]);

	for (i = 0; i < ECC_KEY_WCNT; i++)
		nu_write_reg(ECC_Y2(i), reg_map[ECC_Y2(i) / 4]);

	for (i = 0; i < ECC_KEY_WCNT; i++)
		nu_write_reg(ECC_A(i), reg_map[ECC_A(i) / 4]);

	for (i = 0; i < ECC_KEY_WCNT; i++)
		nu_write_reg(ECC_B(i), reg_map[ECC_B(i) / 4]);

	for (i = 0; i < ECC_KEY_WCNT; i++)
		nu_write_reg(ECC_N(i), reg_map[ECC_N(i) / 4]);

	for (i = 0; i < ECC_KEY_WCNT; i++)
		nu_write_reg(ECC_K(i), reg_map[ECC_K(i) / 4]);

	nu_write_reg(ECC_CTL, reg_map[ECC_CTL / 4]);

	tee_time_get_sys_time(&t_start);
	while ((nu_read_reg(ECC_STS) & ECC_STS_BUSY) ||
	       !(nu_read_reg(INTSTS) & (INTSTS_ECCIF | INTSTS_ECCEIF))) {
		if (is_timeout(&t_start, 500) == true)
			return TEE_ERROR_CRYPTO_BUSY;
	}

	nu_write_reg(INTSTS, (INTSTS_ECCIF | INTSTS_ECCEIF));

	for (i = 0; i < ECC_KEY_WCNT; i++)
		reg_map[ECC_X1(i) / 4] = nu_read_reg(ECC_X1(i));

	for (i = 0; i < ECC_KEY_WCNT; i++)
		reg_map[ECC_Y1(i) / 4] = nu_read_reg(ECC_Y1(i));

	for (i = 0; i < ECC_KEY_WCNT; i++)
		reg_map[ECC_X2(i) / 4] = nu_read_reg(ECC_X2(i));

	for (i = 0; i < ECC_KEY_WCNT; i++)
		reg_map[ECC_Y2(i) / 4] = nu_read_reg(ECC_Y2(i));

	return TEE_SUCCESS;
}

static TEE_Result tsi_rsa_run(uint32_t types,
			      TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t  *reg_map;
	uint32_t  reg_map_pa;
	uint32_t  rsa_ctl, rsa_ksctl;
	int       ret;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE)) {
		EMSG("bad parameters types: 0x%" PRIx32, types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	reg_map = params[1].memref.buffer;
	reg_map_pa = (uint32_t)virt_to_phys(reg_map);

	rsa_ctl = reg_map[RSA_CTL / 4];
	rsa_ksctl = reg_map[RSA_KSCTL / 4];

	memcpy((uint8_t *)&reg_map[0x1000 / 4],
	       (uint8_t *)((uint64_t)reg_map[RSA_SADDR0 / 4]), 0x200);
	memcpy((uint8_t *)&reg_map[0x1200 / 4],
	       (uint8_t *)((uint64_t)reg_map[RSA_SADDR1 / 4]), 0x200);
	memcpy((uint8_t *)&reg_map[0x1400 / 4],
	       (uint8_t *)((uint64_t)reg_map[RSA_SADDR2 / 4]), 0x200);
	memcpy((uint8_t *)&reg_map[0x1600 / 4],
	       (uint8_t *)((uint64_t)reg_map[RSA_SADDR3 / 4]), 0x200);
	memcpy((uint8_t *)&reg_map[0x1800 / 4],
	       (uint8_t *)((uint64_t)reg_map[RSA_SADDR4 / 4]), 0x200);

	reg_map[0x2800 / 4] = reg_map[RSA_KSSTS0 / 4];
	reg_map[0x2804 / 4] = reg_map[RSA_KSSTS1 / 4];

	cache_operation(TEE_CACHEFLUSH,
			(void *)((uint64_t)reg_map + 0x1000), 1728);
	cache_operation(TEE_CACHEINVALIDATE,
			(void *)((uint64_t)reg_map + 0x3000), 1152);

	ret = TSI_RSA_Exp_Mod((rsa_ctl & RSA_CTL_KEYLENG_MASK) >>
			RSA_CTL_KEYLENG_OFFSET,         /* rsa_len    */
		(rsa_ctl & RSA_CTL_CRT) ? 1 : 0,	/* crt        */
		(rsa_ksctl & RSA_KSCTL_RSRC) ? 2 : 3,   /* esel       */
		(rsa_ksctl & RSA_KSCTL_NUM_MASK) >>
			RSA_KSCTL_NUM_OFFSET,           /* e_knum     */
		reg_map_pa + 0x1000,                    /* param_addr */
		reg_map_pa + 0x3000                     /* dest_addr  */
		);

	if (ret != ST_SUCCESS)
		return TEE_ERROR_CRYPTO_FAIL;

	memcpy((uint8_t *)((uint64_t)reg_map[RSA_DADDR / 4]),
	       (uint8_t *)&reg_map[0x3000 / 4], 0x200);

	return TEE_SUCCESS;
}

static TEE_Result ma35d1_rsa_run(uint32_t types,
				  TEE_Param params[TEE_NUM_PARAMS])
{
	vaddr_t   crypto_base = core_mmu_get_va(CRYPTO_BASE, MEM_AREA_IO_SEC);
	uint32_t  *reg_map;
	TEE_Time  t_start;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE)) {
		EMSG("bad parameters types: 0x%" PRIx32, types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	tee_time_get_sys_time(&t_start);
	while (nu_read_reg(RSA_STS) & RSA_STS_BUSY) {
		if (is_timeout(&t_start, 500) == true)
			return TEE_ERROR_CRYPTO_BUSY;
	}

	reg_map = params[1].memref.buffer;

	nu_write_reg(RSA_CTL, 0);
	nu_write_reg(INTSTS, (INTSTS_RSAIF | INTSTS_RSAEIF));

	nu_write_reg(RSA_KSCTL, reg_map[RSA_KSCTL / 4]);
	nu_write_reg(RSA_KSSTS0, reg_map[RSA_KSSTS0 / 4]);
	nu_write_reg(RSA_KSSTS1, reg_map[RSA_KSSTS1 / 4]);

	nu_write_reg(RSA_SADDR0, reg_map[RSA_SADDR0 / 4]);
	nu_write_reg(RSA_SADDR1, reg_map[RSA_SADDR1 / 4]);
	nu_write_reg(RSA_SADDR2, reg_map[RSA_SADDR2 / 4]);
	nu_write_reg(RSA_SADDR3, reg_map[RSA_SADDR3 / 4]);
	nu_write_reg(RSA_SADDR4, reg_map[RSA_SADDR4 / 4]);
	nu_write_reg(RSA_DADDR, reg_map[RSA_DADDR / 4]);
	nu_write_reg(RSA_MADDR0, reg_map[RSA_MADDR0 / 4]);
	nu_write_reg(RSA_MADDR1, reg_map[RSA_MADDR1 / 4]);
	nu_write_reg(RSA_MADDR2, reg_map[RSA_MADDR2 / 4]);
	nu_write_reg(RSA_MADDR3, reg_map[RSA_MADDR3 / 4]);
	nu_write_reg(RSA_MADDR4, reg_map[RSA_MADDR4 / 4]);
	nu_write_reg(RSA_MADDR5, reg_map[RSA_MADDR5 / 4]);
	nu_write_reg(RSA_MADDR6, reg_map[RSA_MADDR6 / 4]);

	nu_write_reg(RSA_CTL, reg_map[RSA_CTL / 4]);

	tee_time_get_sys_time(&t_start);
	while ((nu_read_reg(RSA_STS) & RSA_STS_BUSY) ||
	       (nu_read_reg(RSA_CTL) & RSA_CTL_START)) {
		if (is_timeout(&t_start, RSA_BUSY_TIMEOUT) == true)
			return TEE_ERROR_CRYPTO_BUSY;
	}
	return TEE_SUCCESS;
}

static TEE_Result invoke_command(void *pSessionContext __unused,
				 uint32_t nCommandID, uint32_t nParamTypes,
				 TEE_Param pParams[TEE_NUM_PARAMS])
{
	vaddr_t sys_base = core_mmu_get_va(SYS_BASE, MEM_AREA_IO_SEC);
	int   tsi_en;

	FMSG("command entry point for pseudo-TA \"%s\"", PTA_NAME);

	if (io_read32(sys_base + SYS_CHIPCFG) & TSIEN)
		tsi_en = 1;
	else
		tsi_en = 0;

	switch (nCommandID) {
	case PTA_CMD_CRYPTO_INIT:
		return ma35d1_crypto_init();

	case PTA_CMD_CRYPTO_OPEN_SESSION:
		if (tsi_en)
			return tsi_open_session(nParamTypes, pParams);
		else
			return TEE_SUCCESS;

	case PTA_CMD_CRYPTO_CLOSE_SESSION:
		if (tsi_en)
			return tsi_close_session(nParamTypes, pParams);
		else
			return TEE_SUCCESS;

	case PTA_CMD_CRYPTO_AES_RUN:
		if (tsi_en)
			return tsi_aes_run(nParamTypes, pParams);
		else
			return ma35d1_aes_run(nParamTypes, pParams);

	case PTA_CMD_CRYPTO_SHA_START:
		if (tsi_en)
			return tsi_sha_start(nParamTypes, pParams);
		else
			return TEE_SUCCESS;

	case PTA_CMD_CRYPTO_SHA_UPDATE:
		if (tsi_en)
			return tsi_sha_update(nParamTypes, pParams);
		else
			return ma35d1_sha_update(nParamTypes, pParams);

	case PTA_CMD_CRYPTO_SHA_FINAL:
		if (tsi_en)
			return tsi_sha_final(nParamTypes, pParams);
		else
			return ma35d1_sha_update(nParamTypes, pParams);

	case PTA_CMD_CRYPTO_ECC_PMUL:
		if (tsi_en)
			return tsi_ecc_pmul(nParamTypes, pParams);
		else
			return ma35d1_ecc_pmul(nParamTypes, pParams);

	case PTA_CMD_CRYPTO_RSA_RUN:
		if (tsi_en)
			return tsi_rsa_run(nParamTypes, pParams);
		else
			return ma35d1_rsa_run(nParamTypes, pParams);

	default:
		break;
	}

	return TEE_ERROR_NOT_IMPLEMENTED;
}

pseudo_ta_register(.uuid = PTA_CRYPTO_UUID, .name = PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS | TA_FLAG_DEVICE_ENUM,
		   .invoke_command_entry_point = invoke_command);
