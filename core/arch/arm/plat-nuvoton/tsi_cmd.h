// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020 Nuvoton Technology Corp. All rights reserved.
 */
#ifndef __TSI_CMD_H__
#define __TSI_CMD_H__

/*------------------------------------------------------------------*/
/*  TSI command class code                                          */
/*------------------------------------------------------------------*/
#define C_CODE_TSI_CTRL         0x01
#define C_CODE_TRNG             0x02
#define C_CODE_PRNG             0x03
#define C_CODE_AES              0x04
#define C_CODE_SHA              0x05
#define C_CODE_ECC              0x06
#define C_CODE_RSA              0x07
#define C_CODE_KS               0x08
#define C_CODE_OTP              0x09

/*------------------------------------------------------------------*/
/*  TSI commands                                                    */
/*------------------------------------------------------------------*/
#define CMD_TSI_SYNC            0x0101
#define CMD_TSI_GET_VERSION     0x0102
#define CMD_TSI_SET_CLOCK       0x0110
#define CMD_TSI_RESET           0x0111
#define CMD_TSI_CONFIG_UART     0x0130
#define CMD_TSI_LOAD_EX_FUNC    0x0140
#define CMD_TSI_MONITOR_SET     0x0142
#define CMD_TSI_MONITOR_STATUS  0x0143
#define CMD_TSI_MONITOR_CLOSE   0x0144
#define CMD_TSI_OPEN_SESSION    0x0150
#define CMD_TSI_CLOSE_SESSION   0x0151
#define CMD_TRNG_INIT           0x0201
#define CMD_TRNG_GEN_RANDOM     0x0205
#define CMD_PRNG_RESEED         0x0301
#define CMD_PRNG_GEN_RANDOM     0x0305
#define CMD_PRNG_GEN_RAN_MASS   0x0315
#define CMD_PRNG_GEN_KS_SRAM    0x0320
#define CMD_AES_SET_MODE        0x0401
#define CMD_AES_SET_IV          0x0402
#define CMD_AES_SET_KEY         0x0403
#define CMD_AES_RUN             0x0405
#define CMD_AES_GCM_RUN         0x0406
#define CMD_AES_CCM_RUN         0x0408
#define CMD_AES_ACCESS_FEEDBACK 0x0409
#define CMD_SHA_START           0x0501
#define CMD_SHA_UPDATE          0x0502
#define CMD_SHA_FINISH          0x0503
#define CMD_SHA_ALL_AT_ONCE     0x0505
#define CMD_ECC_GEN_PUB_KEY     0x0601
#define CMD_ECC_GEN_SIG         0x0602
#define CMD_ECC_VERIFY_SIG      0x0603
#define CMD_ECC_MULTIPLY        0x0604
#define CMD_RSA_EXP_MOD         0x0702
#define CMD_KS_WRITE_SRAM_KEY   0x0A01
#define CMD_KS_WRITE_OTP_KEY    0x0A02
#define CMD_KS_READ_KEY         0x0A05
#define CMD_KS_REVOKE_KEY       0x0A08
#define CMD_KS_ERASE_KEY        0x0A10
#define CMD_KS_ERASE_ALL        0x0A11
#define CMD_KS_REMAIN_SIZE      0x0A15
#define CMD_KS_GET_STATUS       0x0A20

#define CMD_EXT_OTP_READ        0xF910
#define	CMD_EXT_RSA_EXP_MOD     0xFE51

/*------------------------------------------------------------------*/
/*  TSI command ACK status                                          */
/*------------------------------------------------------------------*/
#define ST_SUCCESS              0x00
#define ST_WAIT_TSI_SYNC        0x01 /* Waiting host to send TSI_SYNC command    */
#define ST_UNKNOWN_CMD          0x02 /* Unknown command                          */
#define ST_NO_TSI_IMAGE         0x03 /* TSI image is required                    */
#define ST_CMD_QUEUE_FULL       0x04 /* TSI command queue is full                */
#define ST_TIME_OUT             0x10 /* Command request time-out                 */
#define ST_INVALID_PARAM        0x11 /* Invalid parameter                        */
#define ST_NO_AVAIL_SESSION     0x12 /* No available AES/SHA sessions            */
#define ST_INVALID_SESSION_ID   0x13 /* Not an opened AES/SHA session ID         */
#define ST_INVALID_OPERATION    0x14 /* Invalid operation                        */
#define ST_HW_NOT_READY         0x31 /* Hrdawre engine in not ready              */
#define ST_HW_ERROR             0x32 /* Hardware engine report error             */
#define ST_HW_BUSY              0x33 /* Hardware engine is busy on other request */
#define ST_HW_TIME_OUT          0x34 /* Hardware engine time-out                 */
#define ST_BUS_ERROR            0x35 /* Memory address can not access            */
#define ST_KS_ERROR             0x40 /* Key Store key error                      */
#define ST_MON_FULL             0x41 /* All monitors are used.                   */
#define ST_MON_ID_ERR           0x42 /* Invalid monitor ID                       */
#define ST_MON_CHECK_FAIL       0x43 /* Monitor found memory area modified       */
#define ST_IMG_SIZE             0x45 /* Patch image size over limitation         */
#define ST_IMG_VERIFY           0x46 /* Patch image size authentication failed   */
#define ST_ECC_UNKNOWN_CURVE    0x61 /* Unknown ECC curve                        */
#define ST_ECC_INVALID_PRIV_KEY 0x62 /* ECC private key in not valid             */
#define ST_SIG_VERIFY_ERROR     0x70 /* ECC/RSA signature verification failed    */
#define ST_KS_READ_PROTECT      0x80 /* Key Store key entry cannot read by CPU   */
#define ST_KS_FULL              0x81 /* Key Store full                           */
#define ST_KS_ERR               0x82 /* Key Store key general error              */
#define ST_WHC_TX_BUSY          0xd1 /* All TX channel of Wormhole are busy      */
#define ST_CMD_ACK_TIME_OUT     0xd2 /* TSI does not ack command in time limit   */

typedef struct tsi_cmd_t {
	uint32_t	cmd[4];
	uint32_t	ack[4];
	int		tx_channel; /* WHC TX channel used to send this command  */
	uint32_t	tx_jiffy;   /* the jiffy of command being send           */
	int		session_id; /* for AES and SHA only                      */
	uint32_t	addr_param; /* parameter block address                   */
	uint32_t	caddr_src;  /* current data source address               */
	uint32_t	caddr_dst;  /* current data destination address          */
	uint32_t	remain_len; /* remaining data length                     */
} TSI_REQ_T;

enum {
	TREQ_ST_UNUSED = 0,
	TREQ_ST_WAIT_PROCESS,
	TREQ_ST_PROCESSING,
	TREQ_ST_ACK_SEND,
};

#define TC_GET_CLASS_CODE(r)	((((r)->cmd[0]) >> 24) & 0xff)
#define TC_GET_SUB_CODE(r)	((((r)->cmd[0]) >> 16) & 0xff)
#define TC_GET_COMMAND(r)	((((r)->cmd[0]) >> 16) & 0xffff)
#define TC_GET_SESSION_ID(r)	(((r)->cmd[0]) & 0xff)
#define TC_SET_CLASS_CODE(r, c)	((r)->cmd[0]) = (((r)->cmd[0]) & 0x00ffffff) | \
				(((c) & 0xff) << 24)
#define TC_SET_SUB_CODE(r, c)	((r)->cmd[0]) = (((r)->cmd[0]) & 0xff00ffff) | \
				(((c) & 0xff) << 16)
#define TC_SET_SESSION_ID(r, s)	((r)->cmd[0]) = (((r)->cmd[0]) & 0xffffff00) | \
				((s) & 0xff)
#define TA_GET_CLASS_CODE(a)	((((a)->ack[0]) >> 24) & 0xff)
#define TA_GET_SESSION_ID(a)	(((a)->ack[0]) & 0xff)
#define TA_GET_STATUS(a)	((((a)->ack[0]) >> 8) & 0xff)

/* Command/ACK characteristic is composed of class code, sub-code, and session ID */
#define TCK_CHR_MASK			(0xffff00ff)

#define TSI_CMD_WORD0(cc, sc, sid)	(((cc) << 24) | ((sc) << 16) | (sid))

#define CMD_TIME_OUT_1S             1000     /* general time-out 1 seconds */
#define CMD_TIME_OUT_2S             2000     /* general time-out 2 seconds */
#define CMD_TIME_OUT_3S             3000     /* general time-out 3 seconds */
#define CMD_TIME_OUT_5S             5000     /* general time-out 5 seconds */

#define SEL_KEY_FROM_REG            0x0
#define SEL_KEY_FROM_KS_SRAM        0x1
#define SEL_KEY_FROM_KS_OTP         0x5

#define ECC_KEY_SEL_TRNG            0x0
#define ECC_KEY_SEL_KS_OTP          0x1
#define ECC_KEY_SEL_KS_SRAM         0x2
#define ECC_KEY_SEL_USER            0x3

#define RSA_KEY_SEL_KS_OTP          0x1
#define RSA_KEY_SEL_KS_SRAM         0x2
#define RSA_KEY_SEL_USER            0x3

#define AES_KEY_SIZE_128            0UL
#define AES_KEY_SIZE_192            1UL
#define AES_KEY_SIZE_256            2UL

enum {
	CURVE_P_192  = 0x01,
	CURVE_P_224  = 0x02,
	CURVE_P_256  = 0x03,
	CURVE_P_384  = 0x04,
	CURVE_P_521  = 0x05,
	CURVE_K_163  = 0x11,
	CURVE_K_233  = 0x12,
	CURVE_K_283  = 0x13,
	CURVE_K_409  = 0x14,
	CURVE_K_571  = 0x15,
	CURVE_B_163  = 0x21,
	CURVE_B_233  = 0x22,
	CURVE_B_283  = 0x23,
	CURVE_B_409  = 0x24,
	CURVE_B_571  = 0x25,
	CURVE_KO_192 = 0x31,
	CURVE_KO_224 = 0x32,
	CURVE_KO_256 = 0x33,
	CURVE_BP_256 = 0x41,
	CURVE_BP_384 = 0x42,
	CURVE_BP_512 = 0x43,
	CURVE_SM2_256 = 0x50,
	CURVE_25519  = 0x51,
	CURVE_UNDEF,
};

void tsi_print_err_code(int code);

int ma35d1_tsi_init(void);
int TSI_Sync(void);
int TSI_Get_Version(uint32_t *ver_code);
int TSI_Reset(void);
int TSI_Config_UART(uint32_t line, uint32_t baud);
int TSI_Set_Clock(int pllsrc, int clksel);
int TSI_Load_Image(uint32_t base, uint32_t size);
int TSI_Open_Session(int class_code, int *session_id);
int TSI_Close_Session(int class_code, int session_id);
int TSI_TRNG_Init(int method, uint32_t pb_addr);
int TSI_TRNG_Gen_Random(uint32_t wcnt, uint32_t dest_addr);
int TSI_PRNG_ReSeed(int seed_src, uint32_t seed);
int TSI_PRNG_Gen_Random(uint32_t *rnd_w0, uint32_t *rnd_w1);
int TSI_PRNG_Gen_Random_Mass(uint32_t wcnt, uint32_t dest_addr);
int TSI_PRNG_GenTo_KS_SRAM(uint32_t owner, int is_ecdsa, int is_ecdh,
			   uint32_t keysz, int *key_num);
int TSI_AES_Set_Mode(int sid, int kinswap, int koutswap, int inswap,
		     int outswap, int sm4en, int encrypt, int mode,
		     int keysz, int ks, int ks_num);
int TSI_AES_Set_IV(int sid, uint32_t iv_addr);
int TSI_AES_Set_Key(int sid, int keysz, uint32_t key_addr);
int TSI_AES_Run(int sid, int is_last, int data_cnt, uint32_t src_addr,
		uint32_t dest_addr);
int TSI_AES_Run_RM(uint32_t aes_map_addr, uint32_t aes_ksctl);
int TSI_AES_GCM_Run(int sid, int is_last, int data_cnt, uint32_t param_addr);
int TSI_Access_Feedback(int sid, int rw, int wcnt, uint32_t fdbck_addr);
int TSI_SHA_Start(int sid, int inswap, int outswap, int mode_sel, int hmac,
		int mode, int keylen, int ks, int ks_num);
int TSI_SHA_Update(int sid, int data_cnt, uint32_t src_addr);
int TSI_SHA_Finish(int sid, int wcnt, int data_cnt, uint32_t src_addr,
		uint32_t dest_addr);
int TSI_SHA_All_At_Once(int inswap, int outswap, int mode_sel, int mode,
		int wcnt, int data_cnt, uint32_t src_addr,
		uint32_t dest_addr);
int TSI_ECC_GenPublicKey(int curve_id, int is_ecdh, int psel,
		int d_knum, uint32_t priv_key, uint32_t pub_key);
int TSI_ECC_GenSignature(int curve_id, int rsel, int psel, int key_idx,
		uint32_t param_addr, uint32_t sig_addr);
int TSI_ECC_VerifySignature(int curve_id, int psel, int x_knum,
		int y_knum, uint32_t param_addr);
int TSI_ECC_Multiply(int curve_id, int type, int msel, int sps, int m_knum,
		     int x_knum, int y_knum, uint32_t param_addr,
		     uint32_t dest_addr);
int TSI_RSA_Exp_Mod(int rsa_len, int crt, int esel, int e_knum,
		    uint32_t param_addr, uint32_t dest_addr);
int  TSI_KS_Write_SRAM(uint32_t u32Meta, uint32_t au32Key[],
		       uint32_t *iKeyNum);
int  TSI_KS_Write_OTP(int KeyNum, uint32_t u32Meta, uint32_t au32Key[]);
int  TSI_KS_Read(int eType, int32_t i32KeyIdx, uint32_t au32Key[],
		 uint32_t u32WordCnt);
int  TSI_KS_RevokeKey(int eType, int32_t i32KeyIdx);
int  TSI_KS_EraseKey(int eType, int32_t i32KeyIdx);
int  TSI_KS_EraseAll(void);
int  TSI_KS_GetRemainSize(uint32_t *remain_size);
int  TSI_KS_GetStatus(uint32_t *ks_sts, uint32_t *ks_otpsts,
		      uint32_t *ks_metadata);
int  TSI_OTP_Read(uint32_t u32Addr, uint32_t *u32Data);

#endif	/* __TSI_CMD_H__ */
