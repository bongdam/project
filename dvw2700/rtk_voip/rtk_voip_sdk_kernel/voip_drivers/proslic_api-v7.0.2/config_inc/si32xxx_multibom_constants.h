/*
** Copyright (c) 2012 Silicon Laboratories, Inc.
** 2012-05-01 17:48:31
**
** Example use of multiple devices and/or device bom options in which
** presets are generically selected, while the general configuration is
** explicitly selected.
*/


#ifndef SI32XXX_CONSTANTS_H
#define SI32XXX_CONSTANTS_H

/** Ringing Presets */
enum {
	RING_MAX_VBAT_PROVISIONING,
	RING_F20_45VRMS_0VDC_LPR,
	RING_F20_45VRMS_0VDC_BAL
};

/** DC_Feed Presets */
enum {
	DCFEED_48V_20MA,
	DCFEED_48V_25MA,
	DCFEED_PSTN_DET_1,
	DCFEED_PSTN_DET_2
};

/** Impedance Presets */
enum {
	ZSYN_600_0_0_30_0,
	ZSYN_270_750_150_30_0,
	ZSYN_370_620_310_30_0,
	ZSYN_220_820_120_30_0,
	ZSYN_600_0_1000_30_0,
	ZSYN_200_680_100_30_0,
	ZSYN_220_820_115_30_0,
	WB_ZSYN_600_0_0_20_0
};

/** FSK Presets */
enum {
	DEFAULT_FSK
};

/** Pulse_Metering Presets */
enum {
	DEFAULT_PULSE_METERING
};

/** Tone Presets */
enum {
	TONEGEN_FCC_DIAL,
	TONEGEN_FCC_BUSY,
	TONEGEN_FCC_RINGBACK,
	TONEGEN_FCC_REORDER,
	TONEGEN_FCC_CONGESTION
};

/** PCM Presets */
enum {
	PCM_8ULAW,
	PCM_8ALAW,
	PCM_16LIN,
	PCM_16LIN_WB
};


/** General Parameters */
enum{
  SI3217X_GEN_PARAM_FLYBACK_GDRV,
  SI3217X_GEN_PARAM_PMOS_BUCK_BOOST_VDC_3P0_6P0_GDRV,
  SI3217X_GEN_PARAM_PMOS_BUCK_BOOST_VDC_9P0_24P0_GDRV,
  SI3217X_GEN_PARAM_FLYBACK_NO_GDRV,
  SI3217X_GEN_PARAM_BUCK_BOOST_NO_GDRV,
  SI3217X_GEN_PARAM_PMOS_BUCK_BOOST_VDC_3P0_6P0_NO_GDRV,
  SI3217X_GEN_PARAM_PMOS_BUCK_BOOST_VDC_9P0_24P0_NO_GDRV,
};

enum {
  SI3226_GEN_PARAM_FLYBACK,
  SI3226_GEN_PARAM_QCUK
};

enum {
  SI3226X_GEN_PARAM_FLYBACK,
  SI3226X_GEN_PARAM_TSS,
  SI3226X_GEN_PARAM_TSS_ISO,
  SI3226X_GEN_PARAM_QCUK,
  SI3226X_GEN_PARAM_LCQCUK,
  SI3226X_GEN_PARAM_CUK,
  SI3226X_GEN_PARAM_PMOS_BUCK_BOOST_VDC_4P5_16P0
};


#endif

