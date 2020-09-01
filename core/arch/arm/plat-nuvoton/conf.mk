PLATFORM_FLAVOR ?= MA35D1

include core/arch/arm/cpu/cortex-armv8-0.mk

$(call force,CFG_TEE_CORE_NB_CORE,2)
CFG_TZDRAM_START ?= 0x8f900000
CFG_TZDRAM_SIZE ?=  0x00300000
CFG_SHMEM_START ?=  0x8f800000
CFG_SHMEM_SIZE ?=   0x00100000

$(call force,CFG_NUVOTON_UART,y)
$(call force,CFG_GENERIC_BOOT,y)
$(call force,CFG_PM_STUBS,y)
$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)
$(call force,CFG_WITH_ARM_TRUSTED_FW,y)
$(call force,CFG_ARM64_core,y)

$(call force,CFG_NUVOTON_CRYPTO,y)

supported-ta-targets = ta_arm64

ifeq ($(CFG_ARM64_core),y)
$(call force,CFG_WITH_LPAE,y)
else
$(call force,CFG_ARM32_core,y)
endif

CFG_WITH_STACK_CANARIES ?= y

ifeq ($(PLATFORM_FLAVOR),MA35D1)
# 2**1 = 2 cores per cluster
$(call force,CFG_CORE_CLUSTER_SHIFT,1)
endif
