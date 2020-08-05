/*
 *  Routines to access hardware
 *
 *  Copyright (c) 2013 Realtek Semiconductor Corp.
 *
 *  This module is a confidential and proprietary property of RealTek and
 *  possession or use of this module requires written permission of RealTek.
 */


#ifndef _HAL_PLATFORM_
#define _HAL_PLATFORM_

//#include "platform_autoconf.h"
//#include "core_cm3.h"
//#include "hal_irqn.h"
//#include "hal_peri_on.h"
//#include "RTL8195A_SYS_ON_Bit.h"
//#include "RTL8195A_SYS_ON_Reg.h"
//#include "RTL8195A_PERI_ON_Bit.h"
//#include "RTL8195A_PERI_ON_Reg.h"

//#include "RTL8196F_SYS_Bit.h"
//#include "RTL8196F_SYS_Reg.h"

//#include "hal_pinmux.h"
//#include "hal_spi_flash.h"


// register clock
#define SYSTEM_CLK                  PLATFORM_CLOCK


// system register base address
#define SYSTEM_REG_BASE 			0xB8000000
#define TIMER_CONTROL_REG_BASE		0xB8003100

// register base address
#define SPI_FLASH_CTRL_BASE         0x1FFEF000
#define SPI_FLASH_BASE              0x4000000
#define SDR_SDRAM_BASE              0x30000000
#define SYSTEM_CTRL_BASE            0x40000000
#define PERI_ON_BASE                0x40000000
#define VENDOR_REG_BASE             0x40002800
#define SDR_CTRL_BASE               0x40005000


#define PERIPHERAL_IRQ_STATUS       0x04
#define PERIPHERAL_IRQ_MODE         0x08
#define PERIPHERAL_IRQ_EN           0x0C

#define PERIPHERAL_IRQ_ALL_LEVEL    0

#define TIMER_CLK                   32*1000

//3 Peripheral IP Base Address
// TLP PCIE 0
#define PCIE0_DBI_REG_BASE 			0xB8B00000
#define PCIE0_EXTENDED_REG_BASE 	0xB8B01000
#define PCIE0_CFG0_REG_BASE 		0xB8B10000
#define PCIE0_IO_BASE  				0xB8C00000
#define PCIE0_MEM_BASE 				0xB9000000
// TLP PCIE 1
#define PCIE1_DBI_REG_BASE 			0xB8B20000
#define PCIE1_EXTENDED_REG_BASE		0xB8B21000
#define PCIE1_CFG0_REG_BASE 		0xB8B30000
#define PCIE1_IO_BASE  				0xB8E00000
#define PCIE1_MEM_BASE 				0xBA000000

#define GPIO_REG_BASE               0x40001000
#define TIMER_REG_BASE              0xB8148000
#define LOG_UART_REG_BASE           0xf8002000
#define I2C2_REG_BASE               0x40003400
#define I2C3_REG_BASE               0x40003800
#define ADC_REG_BASE                0x40010000
#define DAC_REG_BASE                0x40011000
#define UART0_REG_BASE              0xB8147000
#define RTKUART0_REG_BASE           0xf8002000
#define UART1_REG_BASE              0xB8147400
#define UART2_REG_BASE              0xB8147800
#define SPI0_REG_BASE               0xb801c000
#define SPI1_REG_BASE               0xb801c100
#define SPI2_REG_BASE               0x40042800
#define I2C0_REG_BASE               0xB801D000
#define I2C1_REG_BASE               0xB801D100
#define RTKI2C0_REG_BASE            0xf8000600
#define SDIO_DEVICE_REG_BASE        0x40050000
#define SDIO_HOST_REG_BASE          0x40058000
#define GDMA0_REG_BASE              0xB801B000
//#define GDMA1_REG_BASE              0x40061000
//#define I2S0_REG_BASE               0x40062000
#define I2S0_REG_BASE               0xB801F000 // 8196f ap soc
#define I2S1_REG_BASE               0x40063000
//#define PCM0_REG_BASE               0x40064000
#define PCM0_REG_BASE               0xB8008000 // 8196f ap soc
#define PCM1_REG_BASE               0x40065000
#define CRYPTO_REG_BASE             0xB800C000 // 8196f ap soc
#define WIFI_REG_BASE               0x40080000
#define USB_OTG_REG_BASE            0x400C0000
#define PWM0_REG_BASE				0xB8000200
#define PWM1_REG_BASE				0xB8000204
#define PWM2_REG_BASE				0xB8000208
#define PWM3_REG_BASE				0xB800020c
#define GTEVENT_REG_BASE			0xB8000210

#define GDMA1_REG_OFF			0x1000
#define I2S1_REG_OFF			0x1000
#define PCM1_REG_OFF			0x1000
#define SSI_REG_OFF				0x100	// 8196f ap soc
#define RUART_REG_OFF			0x400
#define RTKUART_REG_OFF			0x100


enum _BOOT_TYPE_ {
    BOOT_FROM_FLASH = 0,
    BOOT_FROM_SDIO  = 1,        
    BOOT_FROM_USB   = 2,
    BOOT_FROM_RSVD  = 3,    
};

enum _EFUSE_CPU_CLK_ {
    CLK_25M    = 0,
    CLK_200M   = 1,
    CLK_100M   = 2,        
    CLK_50M    = 3,
    CLK_12_5M  = 4,    
    CLK_4M     = 5,    
};


#endif //_HAL_PLATFORM_

