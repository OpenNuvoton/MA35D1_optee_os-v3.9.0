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
#include <platform_config.h>
#include <tee/cache.h>
#include <tsi_cmd.h>
#include <io.h>
#include <string.h>
#include <trng_pta_client.h>

#define PTA_NAME "nvt_trng.pta"

#define USE_GEN_NONCE
#define TRNG_BUSY_TIMEOUT	2000

/*---------------------------------------------------------------------*/
/*  MA35D1 TRNG registers                                             */
/*---------------------------------------------------------------------*/
#define CTRL			(trng_base + 0x000)
#define CTRL_CMD_OFFSET			(0)
#define CTRL_CMD_MASK			(0xf << 0)

#define MODE			(trng_base + 0x004)
#define MODE_SEC_ALG			(0x1 << 0)
#define MODE_PRED_RESET			(0x1 << 3)
#define MODE_ADDIN_PRESENT		(0x1 << 4)
#define MODE_KAT_VEC_OFFSET		(5)
#define MODE_KAT_VEC_MASK		(0x3 << 5)
#define MODE_KAT_SEL_OFFSET		(7)
#define MODE_KAT_SEL_MASK		(0x3 << 7)

#define SMODE			(trng_base + 0x008)
#define SMODE_NONCE			(0x1 << 0)
#define SMODE_MISSION_MODE		(0x1 << 1)
#define SMODE_MAX_REJECTS_OFFSET	(2)
#define SMODE_MAX_REJECTS_MASK		(0xff << 2)
#define SMODE_INDIV_HT_DISABLE_OFFSET	(16)
#define SMODE_INDIV_HT_DISABLE_MASK	(0xff << 16)
#define SMODE_NOISE_COLLECT		(0x1 << 31)

#define STAT			(trng_base + 0x00C)
#define STAT_LAST_CMD_OFFSET		(0)
#define STAT_LAST_CMD_MASK		(0xf << 0)
#define STAT_SEC_ALG			(0x1 << 4)
#define STAT_NONCE_MODE			(0x1 << 5)
#define STAT_MISSION_MODE		(0x1 << 6)
#define STAT_DRBG_STATE_OFFSET		(7)
#define STAT_DRBG_STATE_MASK		(0x3 << 7)
#define STAT_STARTUP_TEST_STUCK		(0x1 << 9)
#define STAT_STARTUP_TEST_IN_PROG	(0x1 << 10)
#define STAT_BUSY			(0x1 << 31)

#define IE			(trng_base + 0x010)
#define IE_ZEROIZED			(0x1 << 0)
#define IE_KAT_COMPLETED		(0x1 << 1)
#define IE_NOISE_RDY			(0x1 << 2)
#define IE_ALARMS			(0x1 << 3)
#define IE_DONE				(0x1 << 4)
#define IE_GLBL				(0x1 << 31)

#define ISTAT			(trng_base + 0x014)
#define ISTAT_ZEROIZED			(0x1 << 0)
#define ISTAT_KAT_COMPLETED		(0x1 << 1)
#define ISTAT_NOISE_RDY			(0x1 << 2)
#define ISTAT_ALARMS			(0x1 << 3)
#define ISTAT_DONE			(0x1 << 4)

#define ALARMS			(trng_base + 0x018)
#define ALARMS_FAILED_TEST_ID_OFFSET	(0)
#define ALARMS_FAILED_TEST_ID_MASK	(0xf << 0)
#define ALARMS_ILLEGAL_CMD_SEQ		(0x1 << 4)
#define ALARMS_FAILED_SEED_ST_HT	(0x1 << 5)

#define COREKIT_REL		(trng_base + 0x01C)
#define COREKIT_REL_REL_NUM_OFFSET	(0)
#define COREKIT_REL_REL_NUM_MASK	(0xffff << 0)
#define COREKIT_REL_EXT_VER_OFFSET	(16)
#define COREKIT_REL_EXT_VER_MASK	(0xff << 16)
#define COREKIT_REL_EXT_ENUM_OFFSET	(28)
#define COREKIT_REL_EXT_ENUM_MASK	(0xf << 28)

#define FEATURES		(trng_base + 0x020)
#define FEATURES_SECURE_RST_STATE	(0x1 << 0)
#define FEATURES_DIAG_LEVEL_ST_HLT_OFFSET (1)
#define FEATURES_DIAG_LEVEL_ST_HLT_MASK	(0x7 << 1)
#define FEATURES_DIAG_LEVEL_CLP800_OFFSET (4)
#define FEATURES_DIAG_LEVEL_CLP800_MASK	(0x7 << 4)
#define FEATURES_DIAG_LEVEL_NS		(0x1 << 7)
#define FEATURES_PS_PRESENT		(0x1 << 8)
#define FEATURES_AES_256		(0x1 << 9)
#define RAND(x)			(trng_base + 0x024 + ((x) * 0x04))
#define RAND_WCNT			4
#define NPA_DATA(x)		(trng_base + 0x034 + ((x) * 0x04))
#define NPA_DATA_WCNT			16
#define SEED(x)			(trng_base + 0x074 + ((x) * 0x04))
#define SEED_WCNT			12
#define TIME_TO_SEED		(trng_base + 0x0d0)
#define BUILD_CFG0		(trng_base + 0x0f0)
#define BUILD_CFG1		(trng_base + 0x0f4)

/*
 *  CTL CMD[3:0]  commands
 */
#define TCMD_NOP		0x0       /* Execute a NOP */
#define TCMD_GEN_NOISE		0x1       /* Generate ful-entropy seed from noise  */
#define TCMD_GEN_NONCE		0x2       /* Generate seed from host written nonce */
#define TCMD_CREATE_STATE	0x3       /* Move DRBG to create state  */
#define TCMD_RENEW_STATE	0x4       /* Move DRBG to renew state   */
#define TCMD_REFRESH_ADDIN	0x5       /* Move DRBG to refresh addin */
#define TCMD_GEN_RANDOM		0x6       /* Generate a random number   */
#define TCMD_ADVANCE_STATE	0x7       /* Advance DRBG state         */
#define TCMD_RUN_KAT		0x8       /* Run KAT on DRBG or entropy source */
#define TCMD_ZEROIZE		0xf       /* Zeroize                    */

static int ma35d1_trng_wait_busy_clear(vaddr_t trng_base)
{
	TEE_Time  t_start, t_cur;
	uint32_t  mytime;

	tee_time_get_sys_time(&t_start);
	while (io_read32(STAT) & STAT_BUSY) {
		tee_time_get_sys_time(&t_cur);
		mytime = (t_cur.seconds - t_start.seconds) * 1000 +
		    (int)t_cur.millis - (int)t_start.millis;

		if (mytime > TRNG_BUSY_TIMEOUT)
			return -1;
	}
	return 0;
}

static int ma35d1_trng_issue_command(vaddr_t trng_base, int cmd)
{
	TEE_Time  t_start, t_cur;
	uint32_t  mytime;

	if (ma35d1_trng_wait_busy_clear(trng_base) != 0)
		return TEE_ERROR_TRNG_BUSY;

	io_write32(CTRL, (io_read32(CTRL) &
		   ~CTRL_CMD_MASK) | (cmd << CTRL_CMD_OFFSET));

	tee_time_get_sys_time(&t_start);
	while (!(io_read32(ISTAT) & ISTAT_DONE)) {
		tee_time_get_sys_time(&t_cur);
		mytime = (t_cur.seconds - t_start.seconds) * 1000 +
		    (int)t_cur.millis - (int)t_start.millis;

		if (mytime > TRNG_BUSY_TIMEOUT) {
			EMSG("TRNG command %d timeout! ISTAT=0x%x, SMODE=0x%x.\n",
			     cmd, io_read32(ISTAT),
			     io_read32(SMODE));
			return TEE_ERROR_TRNG_COMMAND;
		}
	}
	return 0;
}

static int ma35d1_trng_gen_nonce(vaddr_t trng_base, uint32_t *nonce)
{
	int   i, j, loop, ret;

	io_write32(SMODE, io_read32(SMODE) | SMODE_NONCE);

	if (io_read32(MODE) & MODE_SEC_ALG)
		loop = 3;
	else
		loop = 2;

	for (i = 0; i < loop; i++) {
		if (ma35d1_trng_wait_busy_clear(trng_base) != 0)
			return TEE_ERROR_TRNG_BUSY;

		for (j = 0; j < 16; j++)
			io_write32(NPA_DATA(j), nonce[j]);

		ret = ma35d1_trng_issue_command(trng_base, TCMD_GEN_NONCE);
		if (ret != 0)
			return TEE_ERROR_TRNG_GEN_NOISE;
	}
	return 0;
}

static int ma35d1_trng_create_state(vaddr_t trng_base)
{
	if (ma35d1_trng_wait_busy_clear(trng_base) != 0)
		return TEE_ERROR_TRNG_BUSY;

	return ma35d1_trng_issue_command(trng_base, TCMD_CREATE_STATE);
}

static TEE_Result ma35d1_trng_init(uint32_t types,
				    TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t nonce[16] =  { 0xaf5781ca, 0xc5b733e2, 0x98cb7a6f, 0xb095a073,
				0x4562a67f, 0x5443ca1a, 0x845a2c0b, 0x74223a2b,
				0x398ce2a7, 0x93c5b66a, 0x56567ac1, 0xcb3eaa16,
				0xda47f33b, 0x456a2e5b, 0xc44d56ae, 0x778d3c1a };
	vaddr_t sys_base = core_mmu_get_va(SYS_BASE, MEM_AREA_IO_SEC);
	vaddr_t trng_base = core_mmu_get_va(TRNG_BASE, MEM_AREA_IO_SEC);
	vaddr_t tsi_base = core_mmu_get_va(TSI_BASE, MEM_AREA_IO_SEC);
	int	ret;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE)) {
		EMSG("bad parameters types: 0x%" PRIx32, types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (io_read32(sys_base + SYS_CHIPCFG) & TSIEN) {

		ret = ma35d1_tsi_init();
		if (ret != 0)
			return ret;

		ret = TSI_TRNG_Init(1, (uint32_t)((uint64_t)nonce));
		if (ret == ST_WAIT_TSI_SYNC) {
			if (TSI_Sync() != ST_SUCCESS)
				return TEE_ERROR_TRNG_BUSY;
			ret = TSI_TRNG_Init(1, (uint32_t)((uint64_t)nonce));
		}
		if (ret != ST_SUCCESS)
			return TEE_ERROR_TRNG_GEN_NOISE;

		FMSG("TSI_TRNG init done.\n");
		return TEE_SUCCESS;
	}

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

	/* enable TRNG engine clock */
	io_write32(tsi_base + 0x20c, io_read32(tsi_base + 0x20c) |
		   (1 << 25));

	if (ma35d1_trng_wait_busy_clear(trng_base) != 0)
		return TEE_ERROR_TRNG_BUSY;

	if (io_read32(STAT) & (STAT_STARTUP_TEST_STUCK |
		STAT_STARTUP_TEST_IN_PROG)) {
		/* TRNG startup in progress state! */
		return TEE_ERROR_TRNG_BUSY;
	}

	/* SELECT_ALG_AES_256 */
	io_write32(MODE, io_read32(MODE) | MODE_SEC_ALG);

	ret = ma35d1_trng_gen_nonce(trng_base, nonce);
	if (ret != 0)
		return ret;

	ret = ma35d1_trng_create_state(trng_base);
	if (ret != 0)
		return ret;

	params[0].value.a = io_read32(STAT);
	params[0].value.b = io_read32(ISTAT);

	FMSG("TRNG init done.\n");
	return TEE_SUCCESS;
}

static TEE_Result ma35d1_trng_read(uint32_t types,
                                    TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t *rdata = NULL;
	uint32_t rq_size = 0, get_size = 0;
	vaddr_t sys_base = core_mmu_get_va(SYS_BASE, MEM_AREA_IO_SEC);
	vaddr_t trng_base = core_mmu_get_va(TRNG_BASE, MEM_AREA_IO_SEC);
	int	i, ret;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE)) {
		EMSG("bad parameters types: 0x%" PRIx32, types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	rq_size = params[0].memref.size;

	if (rq_size % 4)	/* must be multiple of words */
		return TEE_ERROR_NOT_SUPPORTED;

	rdata = (uint32_t *)params[0].memref.buffer;
	if (!rdata)
		return TEE_ERROR_BAD_PARAMETERS;

	if ((io_read32(sys_base + SYS_CHIPCFG) & TSIEN)) {
		/*
		 * TSI enabled. Invoke TSI command and return here.
		 */
		cache_operation(TEE_CACHEINVALIDATE, rdata, rq_size);

		ret = TSI_TRNG_Gen_Random(rq_size / 4,
					  (uint32_t)virt_to_phys(rdata));
		if (ret != ST_SUCCESS)
			return TEE_ERROR_TRNG_FAILED;

		return 0;
	}

	while (rq_size >= 4) {
		if (ma35d1_trng_wait_busy_clear(trng_base) != 0)
			return TEE_ERROR_TRNG_BUSY;

		ret = ma35d1_trng_issue_command(trng_base, TCMD_GEN_RANDOM);
		if (ret != 0)
			return ret;

		for (i = 0; i < 4; i++) {
			if (rq_size < 4)
				break;
			*rdata = io_read32(RAND(i));
			rdata++;
			rq_size -= 4;
			get_size += 4;
		}
	}
	params[0].memref.size = get_size;
	FMSG("reqsize = %d, get_size=%d\n", rq_size, get_size);
	return 0;
}

static TEE_Result invoke_command(void *pSessionContext __unused,
				 uint32_t nCommandID, uint32_t nParamTypes,
				 TEE_Param pParams[TEE_NUM_PARAMS])
{
	FMSG("command entry point for pseudo-TA \"%s\"", PTA_NAME);

	switch (nCommandID) {
	case PTA_CMD_TRNG_INIT:
		return ma35d1_trng_init(nParamTypes, pParams);
	
	case PTA_CMD_TRNG_READ:
		return ma35d1_trng_read(nParamTypes, pParams);
	default:
		break;
	}

	return TEE_ERROR_NOT_IMPLEMENTED;
}

pseudo_ta_register(.uuid = PTA_TRNG_UUID, .name = PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS | TA_FLAG_DEVICE_ENUM,
		   .invoke_command_entry_point = invoke_command);
