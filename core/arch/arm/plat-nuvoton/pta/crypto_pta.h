/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2020 Nuvoton Technology Corp. All rights reserved.
 */
#ifndef __CRYPTO_PTA_H
#define __CRYPTO_PTA_H

#define INTEN			0x000
#define INTEN_AESIEN			(0x1 << 0)
#define INTEN_AESEIEN			(0x1 << 1)
#define INTEN_PRNGIEN			(0x1 << 16)
#define INTEN_ECCIEN			(0x1 << 22)
#define INTEN_ECCEIEN			(0x1 << 23)
#define INTEN_HMACIEN			(0x1 << 24)
#define INTEN_HMACEIEN			(0x1 << 25)
#define INTEN_RSAIEN			(0x1 << 30)
#define INTEN_RSAEIEN			(0x1 << 31)
#define INTSTS			0x004
#define INTSTS_AESIF			(0x1 << 0)
#define INTSTS_AESEIF			(0x1 << 1)
#define INTSTS_PRNGIF			(0x1 << 16)
#define INTSTS_ECCIF			(0x1 << 22)
#define INTSTS_ECCEIF			(0x1 << 23)
#define INTSTS_HMACIF			(0x1 << 24)
#define INTSTS_HMACEIF			(0x1 << 25)
#define INTSTS_RSAIF			(0x1 << 30)
#define INTSTS_RSAEIF			(0x1 << 31)

#define PRNG_CTL		0x008
#define PRNG_CTL_START			(0x1 << 0)
#define PRNG_CTL_SEEDRLD		(0x1 << 1)
#define PRNG_CTL_KEYSZ_OFFSET		(2)
#define PRNG_CTL_KEYSZ_MASK		(0xf << 2)
#define PRNG_CTL_BUSY			(0x1 << 8)
#define PRNG_CTL_SEEDSRC		(0x1 << 16)
#define PRNG_SEED		0x00C
#define PRNG_KEY(x)		(0x010 + ((x) * 0x04))

#define AES_FDBCK(x)		(0x050 + ((x) * 0x04))
#define AES_GCM_IVCNT(x)	(0x080 + ((x) * 0x04))
#define AES_GCM_ACNT(x)		(0x088 + ((x) * 0x04))
#define AES_GCM_PCNT(x)		(0x090 + ((x) * 0x04))
#define AES_FBADDR		0x0A0
#define AES_CTL			0x100
#define AES_CTL_START			(0x1 << 0)
#define AES_CTL_STOP			(0x1 << 1)
#define AES_CTL_KEYSZ_OFFSET		2
#define AES_CTL_KEYSZ_MASK		(0x3 << 2)
#define AES_CTL_DMALAST			(0x1 << 5)
#define AES_CTL_DMACSCAD		(0x1 << 6)
#define AES_CTL_DMAEN			(0x1 << 7)
#define AES_CTL_OPMODE_OFFSET		8
#define AES_CTL_OPMODE_MASK		(0xff << 8)
#define AES_CTL_ENCRPT			(0x1 << 16)
#define AES_CTL_SM4EN			(0x1 << 17)
#define AES_CTL_FBIN			(0x1 << 20)
#define AES_CTL_FBOUT			(0x1 << 21)
#define AES_CTL_OUTSWAP			(0x1 << 22)
#define AES_CTL_INSWAP			(0x1 << 23)
#define AES_CTL_KOUTSWAP		(0x1 << 24)
#define AES_CTL_KINSWAP			(0x1 << 25)
#define AES_STS			0x104
#define AES_STS_BUSY			(0x1 << 0)
#define AES_STS_INBUFEMPTY		(0x1 << 8)
#define AES_STS_INBUFFULL		(0x1 << 9)
#define AES_STS_INBUFERR		(0x1 << 10)
#define AES_STS_CNTERR			(0x1 << 12)
#define AES_STS_OUTBUFEMPTY		(0x1 << 16)
#define AES_STS_OUTBUFFULL		(0x1 << 17)
#define AES_STS_OUTBUFERR		(0x1 << 18)
#define AES_STS_BUSERR			(0x1 << 20)
#define AES_STS_KSERR			(0x1 << 21)
#define AES_DATIN		0x108
#define AES_DATOUT		0x10C
#define AES_KEY(x)		(0x110 + ((x) * 0x04))
#define AES_IV(x)		(0x130 + ((x) * 0x04))
#define AES_SADDR		0x140
#define AES_DADDR		0x144
#define AES_CNT			0x148

#define HMAC_CTL		0x300
#define HMAC_CTL_START			(0x1 << 0)
#define HMAC_CTL_STOP			(0x1 << 1)
#define HMAC_CTL_DMAFIRST		(0x1 << 4)
#define HMAC_CTL_DMALAST		(0x1 << 5)
#define HMAC_CTL_DMACSCAD		(0x1 << 6)
#define HMAC_CTL_DMAEN			(0x1 << 7)
#define HMAC_CTL_OPMODE_OFFSET		8
#define HMAC_CTL_OPMODE_MASK		(0x7 << 8)
#define HMAC_CTL_HMACEN			(0x1 << 11)
#define HMAC_CTL_SHA3EN			(0x1 << 12)
#define HMAC_CTL_SM3EN			(0x1 << 13)
#define HMAC_CTL_MD5EN			(0x1 << 14)
#define HMAC_CTL_FBIN			(0x1 << 20)
#define HMAC_CTL_FBOUT			(0x1 << 21)
#define HMAC_CTL_OUTSWAP		(0x1 << 22)
#define HMAC_CTL_INSWAP			(0x1 << 23)
#define HMAC_CTL_NEXTDGST		(0x1 << 24)
#define HMAC_CTL_FINISHDGST		(0x1 << 25)
#define HMAC_STS		0x304
#define HMAC_STS_BUSY			(0x1 << 0)
#define HMAC_STS_DMABUSY		(0x1 << 1)
#define HMAC_STS_SHAKEBUSY		(0x1 << 2)
#define HMAC_STS_DMAERR			(0x1 << 8)
#define HMAC_STS_KSERR			(0x1 << 9)
#define HMAC_STS_DATINREQ		(0x1 << 16)
#define HMAC_DGST(x)		(0x308 + ((x) * 0x04))
#define HMAC_KEYCNT		0x348
#define HMAC_SADDR		0x34C
#define HMAC_DMACNT		0x350
#define HMAC_DATIN		0x354
#define HMAC_FDBCK(x)		(0x358 + ((x) * 0x04))
#define HMAC_FDBCK_WCNT			88
#define HMAC_FBADDR		0x4FC
#define HMAC_SHAKEDGST(x)	(0x500 + ((x) * 0x04))
#define HMAC_SHAKEDGST_WCNT		42

#define ECC_CTL			0x800
#define ECC_CTL_START			(0x1 << 0)
#define ECC_CTL_STOP			(0x1 << 1)
#define ECC_CTL_ECDSAS			(0x1 << 4)
#define ECC_CTL_ECDSAR			(0x1 << 5)
#define ECC_CTL_DMAEN			(0x1 << 7)
#define ECC_CTL_FSEL			(0x1 << 8)
#define ECC_CTL_ECCOP_OFFSET		9
#define ECC_CTL_ECCOP_MASK		(0x3 << 9)
#define ECC_CTL_MODOP_OFFSET		11
#define ECC_CTL_MODOP_MASK		(0x3 << 9)
#define ECC_CTL_CSEL			(0x1 << 13)
#define ECC_CTL_SCAP			(0x1 << 14)
#define ECC_CTL_LDAP1			(0x1 << 16)
#define ECC_CTL_LDAP2			(0x1 << 17)
#define ECC_CTL_LDA			(0x1 << 18)
#define ECC_CTL_LDB			(0x1 << 19)
#define ECC_CTL_LDN			(0x1 << 20)
#define ECC_CTL_LDK			(0x1 << 21)
#define ECC_CTL_CURVEM_OFFSET		22
#define ECC_CTL_CURVEM_MASK		(0x3ff << 22)
#define ECC_STS			0x804
#define ECC_STS_BUSY			(0x1 << 0)
#define ECC_STS_DMABUSY			(0x1 << 1)
#define ECC_STS_BUSERR			(0x1 << 16)
#define ECC_STS_KSERR			(0x1 << 17)
#define HMAC_DGST(x)		(0x308 + ((x) * 0x04))
#define ECC_X1(x)		(0x808 + ((x) * 0x04))
#define ECC_Y1(x)		(0x850 + ((x) * 0x04))
#define ECC_X2(x)		(0x898 + ((x) * 0x04))
#define ECC_Y2(x)		(0x8E0 + ((x) * 0x04))
#define ECC_A(x)		(0x928 + ((x) * 0x04))
#define ECC_B(x)		(0x970 + ((x) * 0x04))
#define ECC_N(x)		(0x9B8 + ((x) * 0x04))
#define ECC_K(x)		(0xA00 + ((x) * 0x04))
#define ECC_KEY_WCNT			18
#define ECC_SADDR		0xA48
#define ECC_DADDR		0xA4C
#define ECC_STARTREG		0xA50
#define ECC_WORDCNT		0xA54

#define RSA_CTL			0xB00
#define RSA_CTL_START			(0x1 << 0)
#define RSA_CTL_STOP			(0x1 << 1)
#define RSA_CTL_CRT			(0x1 << 2)
#define RSA_CTL_CRTBYP			(0x1 << 3)
#define RSA_CTL_KEYLENG_OFFSET		4
#define RSA_CTL_KEYLENG_MASK		(0x3 << 4)
#define RSA_CTL_SCAP			(0x1 << 8)
#define RSA_STS			0xB04
#define RSA_STS_BUSY			(0x1 << 0)
#define RSA_STS_DMABUSY			(0x1 << 1)
#define RSA_STS_BUSERR			(0x1 << 16)
#define RSA_STS_CTLERR			(0x1 << 17)
#define RSA_STS_KSERR			(0x1 << 18)
#define RSA_SADDR0		0xB08
#define RSA_SADDR1		0xB0C
#define RSA_SADDR2		0xB10
#define RSA_SADDR3		0xB14
#define RSA_SADDR4		0xB18
#define RSA_DADDR		0xB1C
#define RSA_MADDR0		0xB20
#define RSA_MADDR1		0xB24
#define RSA_MADDR2		0xB28
#define RSA_MADDR3		0xB2C
#define RSA_MADDR4		0xB30
#define RSA_MADDR5		0xB34
#define RSA_MADDR6		0xB38

#define PRNG_KSCTL		0xF00
#define PRNG_KSCTL_NUM_OFFSET		0
#define PRNG_KSCTL_NUM_MASK		(0x1f << 0)
#define PRNG_KSCTL_KEYSRC		(0x1 << 8)
#define PRNG_KSCTL_TRUST		(0x1 << 16)
#define PRNG_KSCTL_PRIV			(0x1 << 18)
#define PRNG_KSCTL_ECDH			(0x1 << 19)
#define PRNG_KSCTL_ECDSA		(0x1 << 20)
#define PRNG_KSCTL_WDST			(0x1 << 21)
#define PRNG_KSCTL_WSDST_OFFSET		22
#define PRNG_KSCTL_WSDST_MASK		(0x3 << 22)
#define PRNG_KSCTL_OWNER_OFFSET		24
#define PRNG_KSCTL_OWNER_MASK		(0x7 << 24)
#define PRNG_KSSTS		0xF04
#define PRNG_KSSTS_NUM_OFFSET		0
#define PRNG_KSSTS_NUM_MASK		(0x1f << 0)
#define PRNG_KSSTS_KCTLERR		(0x1 << 16)

#define AES_KSCTL		0xF10
#define AES_KSCTL_NUM_OFFSET		0
#define AES_KSCTL_NUM_MASK		(0x1f << 0)
#define AES_KSCTL_RSRC			(0x1 << 5)
#define AES_KSCTL_RSSRC_OFFSET		6
#define AES_KSCTL_RSSRC_MASK		(0x3 << 6)

#define HMAC_KSCTL		0xF30
#define HMAC_KSCTL_NUM_OFFSET		0
#define HMAC_KSCTL_NUM_MASK		(0x1f << 0)
#define HMAC_KSCTL_RSRC			(0x1 << 5)
#define HMAC_KSCTL_RSSRC_OFFSET		6
#define HMAC_KSCTL_RSSRC_MASK		(0x3 << 6)

#define ECC_KSCTL		0xF40
#define ECC_KSCTL_NUMK_OFFSET		0
#define ECC_KSCTL_NUMK_MASK		(0x1f << 0)
#define ECC_KSCTL_RSRCK			(0x1 << 5)
#define ECC_KSCTL_RSSRCK_OFFSET		6
#define ECC_KSCTL_RSSRCK_MASK		(0x3 << 6)
#define ECC_KSCTL_ECDH			(0x1 << 14)
#define ECC_KSCTL_TRUST			(0x1 << 16)
#define ECC_KSCTL_PRIV			(0x1 << 18)
#define ECC_KSCTL_XY			(0x1 << 20)
#define ECC_KSCTL_WDST			(0x1 << 21)
#define ECC_KSCTL_WSDST_OFFSET		22
#define ECC_KSCTL_WSDST_MASK		(0x3 << 22)
#define ECC_KSCTL_OWNER_OFFSET		24
#define ECC_KSCTL_OWNER_MASK		(0x7 << 24)
#define ECC_KSSTS		0xF44
#define ECC_KSSTS_NUM_OFFSET		0
#define ECC_KSSTS_NUM_MASK		(0x1f << 0)
#define ECC_KSXY			0xF48
#define ECC_KSXY_NUMX_OFFSET		0
#define ECC_KSXY_NUMX_MASK		(0x1f << 0)
#define ECC_KSXY_RSRCXY			(0x1 << 5)
#define ECC_KSXY_RSSRCX_OFFSET		6
#define ECC_KSXY_RSSRCX_MASK		(0x3 << 6)
#define ECC_KSXY_NUMY_OFFSET		8
#define ECC_KSXY_NUMY_MASK		(0x1f << 8)
#define ECC_KSXY_RSSRCY_OFFSET		14
#define ECC_KSXY_RSSRCY_MASK		(0x3 << 14)

#define RSA_KSCTL		0xF50
#define RSA_KSCTL_NUM_OFFSET		0
#define RSA_KSCTL_NUM_MASK		(0x1f << 0)
#define RSA_KSCTL_RSRC			(0x1 << 5)
#define RSA_KSCTL_RSSRC_OFFSET		6
#define RSA_KSCTL_RSSRC_MASK		(0x3 << 6)
#define RSA_KSCTL_BKNUM_OFFSET		8
#define RSA_KSCTL_BKNUM_MASK		(0x1f << 8)
#define RSA_KSSTS0		0xF54
#define RSA_KSSTS0_NUM0_OFFSET		0
#define RSA_KSSTS0_NUM0_MASK		(0x1f << 0)
#define RSA_KSSTS0_NUM1_OFFSET		8
#define RSA_KSSTS0_NUM1_MASK		(0x1f << 8)
#define RSA_KSSTS0_NUM2_OFFSET		16
#define RSA_KSSTS0_NUM2_MASK		(0x1f << 16)
#define RSA_KSSTS0_NUM3_OFFSET		24
#define RSA_KSSTS0_NUM3_MASK		(0x1f << 24)
#define RSA_KSSTS1		0xF58
#define RSA_KSSTS1_NUM4_OFFSET		0
#define RSA_KSSTS1_NUM4_MASK		(0x1f << 0)
#define RSA_KSSTS1_NUM5_OFFSET		8
#define RSA_KSSTS1_NUM5_MASK		(0x1f << 8)
#define RSA_KSSTS1_NUM6_OFFSET		16
#define RSA_KSSTS1_NUM6_MASK		(0x1f << 16)
#define RSA_KSSTS1_NUM7_OFFSET		24
#define RSA_KSSTS1_NUM7_MASK		(0x1f << 24)

#define AES_MODE_ECB			0UL
#define AES_MODE_CBC			1UL
#define AES_MODE_CFB			2UL
#define AES_MODE_OFB			3UL
#define AES_MODE_CTR			4UL
#define AES_MODE_CBC_CS1		0x10UL
#define AES_MODE_CBC_CS2		0x11UL
#define AES_MODE_CBC_CS3		0x12UL
#define AES_MODE_GCM			0x20UL
#define AES_MODE_GHASH			0x21UL
#define AES_MODE_CCM			0x22UL

#define SHA_MODE_SEL_OFFSET		12
#define SHA_MODE_SEL_MASK		(0x7 << 12)
#define SHA_MODE_SEL_SHA1		0UL
#define SHA_MODE_SEL_SHA2		0UL
#define SHA_MODE_SEL_SHA3		1UL
#define SHA_MODE_SEL_SM3		2UL
#define SHA_MODE_SEL_MD5		4UL

#endif /* __CRYPTO_PTA_H */
