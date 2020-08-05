/*
 *  Routines to access hardware
 *
 *  Copyright (c) 2013 Realtek Semiconductor Corp.
 *
 *  This module is a confidential and proprietary property of RealTek and
 *  possession or use of this module requires written permission of RealTek.
 */

#ifndef _RTK_I2C_BASE_H_
#define _RTK_I2C_BASE_H_

#include "hal_api.h"
#include "rtk_i2c_base_bit.h"
#include "rtk_i2c_base_reg.h"


VOID
HalRTKI2CWrite32(
    IN  u8      I2CIdx,
    IN  u8      I2CReg,
    IN  u32     I2CVal
);


u32
HalRTKI2CRead32(
    IN  u8      I2CIdx,
    IN  u8      I2CReg
);


#define HAL_RTK_I2C_WRITE32(I2CIdx, addr, value)    HalRTKI2CWrite32(I2CIdx,addr,value)
#define HAL_RTK_I2C_READ32(I2CIdx, addr)            HalRTKI2CRead32(I2CIdx,addr)
/* //due to DW I2C re-declare.....
//4 I2C debug output
#define I2C_PREFIX      "RTL8195A[i2c]: "
#define I2C_PREFIX_LVL  "    [i2c_DBG]: "

typedef enum _I2C_DBG_LVL_ {
    HAL_I2C_LVL         =   0x01,
    VERI_I2C_LVL        =   0x02,
}I2C_DBG_LVL,*PI2C_DBG_LVL;

#ifdef CONFIG_DEBUG_LOG
#ifdef CONFIG_DEBUG_LOG_I2C_HAL

    #define DBG_8195A_I2C(...)  do{ \
        _DbgDump("\r"I2C_PREFIX __VA_ARGS__);\
    }while(0)


    #define I2CDBGLVL   0xFF   
    #define DBG_8195A_I2C_LVL(LVL,...)  do{\
            if (LVL&I2CDBGLVL){\
                _DbgDump("\r"I2C_PREFIX_LVL __VA_ARGS__);\
            }\
    }while(0)

#else
    #define DBG_I2C_LOG_PERD    100
    #define DBG_8195A_I2C(...)
    #define DBG_8195A_I2C_LVL(...)

#endif
#endif
*/
//4 I2C params
typedef enum _RTK_I2C_SPD_MD_   {
    RTK_SS_MODE         =   1,
    RTK_FS_MODE         =   2,
    RTK_HS_MODE         =   3,
}RTK_I2C_SPD_MD,*PRTK_I2C_SPD_MD;

typedef enum _RTK_I2C_ADDR_MD_   {
    RTK_ADDR_7BIT       =   0,
    RTK_ADDR_10BIT      =   1,  
}RTK_I2C_ADDR_MD,*PRTK_I2C_ADDR_MD;


typedef enum _RTK_I2C_DEV_ADDR_ {
    RTK_I2C0_ADDR       =   0x0010,
    RTK_I2C1_ADDR       =   0x0011,
    RTK_I2C2_ADDR       =   0x0012,
    RTK_I2C3_ADDR       =   0x0013,
}RTK_I2C_DEV_ADDR,*PRTK_I2C_DEV_ADDR;


//4 I2C Module Selection
typedef enum _RTK_I2C_MODULE_SEL_ {
        RTK_I2C0_SEL    =   0x0,
        RTK_I2C1_SEL    =   0x1,
        RTK_I2C2_SEL    =   0x2,
        RTK_I2C3_SEL    =   0x3,
}RTK_I2C_MODULE_SEL,*PRTK_I2C_MODULE_SEL;

#if 0
//4 I2C Pinmux Selection
typedef enum _I2C0_PINMUX_ {
        I2C0_TO_D   =   0x0,
        I2C0_TO_H   =   0x1,
        I2C0_TO_I   =   0x2,
        I2C0_TO_E   =   0x3,
}I2C0_PINMUX, *PI2C0_PINMUX;

typedef enum _I2C1_PINMUX_ {
        I2C1_TO_C   =   0x0,
        I2C1_TO_H   =   0x1,
        I2C1_TO_J   =   0x2,
}I2C1_PINMUX, *PI2C1_PINMUX;

typedef enum _I2C2_PINMUX_ {
        I2C2_TO_B   =   0x0,
        I2C2_TO_E   =   0x1,
        I2C2_TO_J   =   0x2,
}I2C2_PINMUX, *PI2C2_PINMUX;

typedef enum _I2C3_PINMUX_ {
        I2C3_TO_B   =   0x0,
        I2C3_TO_E23 =   0x1,
        I2C3_TO_E45 =   0x2,
        I2C3_TO_IJ  =   0x3,
}I2C3_PINMUX, *PI2C3_PINMUX;
#endif

//4 Hal I2C function prototype
#if 0
BOOL
HalI2CModuleEn(
    IN  VOID    *Data
);
#endif
BOOL
HalI2CInitMasterRTKCommon(
    IN  VOID    *Data
);

#if 0
BOOL
HalI2CInitSlave(
    IN  VOID    *Data
);
#endif
BOOL
HalI2CSetCLKRTKCommon(
    IN  VOID    *Data
);


VOID
HalI2CDATWriteRTKCommon(
    IN  VOID    *Data
);

VOID
HalI2CDATReadRTKCommon(
    IN  VOID    *Data
);

VOID
HalI2CClrIntrRTKCommon(
    IN  VOID    *Data
);

#if 0
VOID
HalI2CClrAllIntr(
    IN  VOID    *Data
);

VOID
HalI2CClrAllIntr(
    IN  VOID    *Data
);
#endif
VOID
HalI2CEnableIntrRTKCommon(
    IN  VOID    *Data
);
#if 0
VOID
HalI2CEnableDMA(
    IN  VOID    *Data
);

VOID
HalI2CDisableDMA(
        IN  VOID    *Data
);
#endif

#endif // _I2C_BASE_H_

