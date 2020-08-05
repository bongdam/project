/*
 *  Routines to access hardware
 *
 *  Copyright (c) 2013 Realtek Semiconductor Corp.
 *
 *  This module is a confidential and proprietary property of RealTek and
 *  possession or use of this module requires written permission of RealTek.
 */


#ifndef _RTK_I2C_BASE_BIT_H_
#define _RTK_I2C_BASE_BIT_H_

//2 REG_RTK_I2C_IC_CMD
#define BIT_IC_CMD_SLVADDR(x)               	(((x) & BIT_MASK_IC_CMD_SLVADDR) << BIT_SHIFT_IC_CMD_SLVADDR)
#define BIT_SHIFT_IC_CMD_SLVADDR         	0
#define BIT_MASK_IC_CMD_SLVADDR          	0x7F
#define BIT_CTRL_IC_CMD_SLVADDR(x)       	(((x) & BIT_MASK_IC_CMD_SLVADDR) << BIT_SHIFT_IC_CMD_SLVADDR)

#define BIT_IC_CMD_AUTOPOLL                  	BIT(7)
#define BIT_SHIFT_IC_CMD_AUTOPOLL            	7
#define BIT_MASK_IC_CMD_AUTOPOLL             	0x1
#define BIT_CTRL_IC_CMD_AUTOPOLL(x)          	(((x) & BIT_MASK_IC_CMD_AUTOPOLL) << BIT_SHIFT_IC_CMD_AUTOPOLL)

#define BIT_IC_CMD_RDLEN(x)                   	(((x) & BIT_MASK_IC_CMD_RDLEN) << BIT_SHIFT_IC_CMD_RDLEN)
#define BIT_SHIFT_IC_CMD_RDLEN             	16
#define BIT_MASK_IC_CMD_RDLEN              	0x7F
#define BIT_CTRL_IC_CMD_RDLEN(x)           	(((x) & BIT_MASK_IC_CMD_RDLEN) << BIT_SHIFT_IC_CMD_RDLEN)

#define BIT_IC_CMD_WRLEN(x)                   	(((x) & BIT_MASK_IC_CMD_WRLEN) << BIT_SHIFT_IC_CMD_WRLEN)
#define BIT_SHIFT_IC_CMD_WRLEN             	23
#define BIT_MASK_IC_CMD_WRLEN              	0x3F
#define BIT_CTRL_IC_CMD_WRLEN(x)           	(((x) & BIT_MASK_IC_CMD_WRLEN) << BIT_SHIFT_IC_CMD_WRLEN)

#define BIT_SHIFT_IC_CMD_REGADDR_LEN 		29
#define BIT_MASK_IC_CMD_REGADDR_LEN			0x07
#define BIT_IC_CMD_REGADDR_LEN(x)           ((x) & BIT_MASK_IC_CMD_REGADDR_LEN) << BIT_SHIFT_IC_CMD_REGADDR_LEN)
#define BIT_CTRL_IC_CMD_REGADDR_LEN(x)      (((x) & BIT_MASK_IC_CMD_REGADDR_LEN) << BIT_SHIFT_IC_CMD_REGADDR_LEN)


//2 REG_RTK_I2C_IC_STATUS
#define BIT_IC_STATUS_INT_STAT            	BIT(0)
#define BIT_SHIFT_IC_STATUS_INT_STAT      	0
#define BIT_MASK_IC_STATUS_INT_STAT       	0x1
#define BIT_CTRL_IC_STATUS_INT_STAT(x)    	(((x) & BIT_MASK_IC_STATUS_INT_STAT) << BIT_SHIFT_IC_STATUS_INT_STAT)

#define BIT_IC_STATUS_INT_MASK            	BIT(1)
#define BIT_SHIFT_IC_STATUS_INT_MASK      	1
#define BIT_MASK_IC_STATUS_INT_MASK       	0x1
#define BIT_CTRL_IC_STATUS_INT_MASK(x)    	(((x) & BIT_MASK_IC_STATUS_INT_MASK) << BIT_SHIFT_IC_STATUS_INT_MASK)

#define BIT_IC_STATUS_AUTOPOLL_FAIL     	BIT(2)
#define BIT_SHIFT_IC_STATUS_AUTOPOLL_FAIL   2
#define BIT_MASK_IC_STATUS_AUTOPOLL_FAIL    0x1
#define BIT_CTRL_IC_STATUS_AUTOPOLL_FAIL(x) (((x) & BIT_MASK_IC_STATUS_AUTOPOLL_FAIL) << BIT_SHIFT_IC_STATUS_AUTOPOLL_FAIL)

#define BIT_IC_STATUS_WR_FAIL               BIT(3)
#define BIT_SHIFT_IC_STATUS_WR_FAIL         3
#define BIT_MASK_IC_STATUS_WR_FAIL          0x1
#define BIT_CTRL_IC_STATUS_WR_FAIL(x)       (((x) & BIT_MASK_IC_STATUS_WR_FAIL) << BIT_SHIFT_IC_STATUS_WR_FAIL)

#define BIT_IC_STATUS_SLVREG_FAIL            BIT(4)
#define BIT_SHIFT_IC_STATUS_SLVREG_FAIL      4
#define BIT_MASK_IC_STATUS_SLVREG_FAIL       0x1
#define BIT_CTRL_IC_STATUS_SLVREG_FAIL(x)    (((x) & BIT_MASK_IC_STATUS_SLVREG_FAIL) << BIT_SHIFT_IC_STATUS_SLVREG_FAIL)

#define BIT_IC_STATUS_SLVADDR_FAIL          BIT(5)
#define BIT_SHIFT_IC_STATUS_SLVADDR_FAIL    5
#define BIT_MASK_IC_STATUS_SLVADDR_FAIL     0x1
#define BIT_CTRL_IC_STATUS_SLVADDR_FAIL(x)  (((x) & BIT_MASK_IC_STATUS_SLVADDR_FAIL) << BIT_SHIFT_IC_STATUS_SLVADDR_FAIL)

#define BIT_IC_STATUS_READY                	BIT(6)
#define BIT_SHIFT_IC_STATUS_READY          	6
#define BIT_MASK_IC_STATUS_READY           	0x1
#define BIT_CTRL_IC_STATUS_READY(x)        	(((x) & BIT_MASK_IC_STATUS_READY) << BIT_SHIFT_IC_STATUS_READY)


//2 REG_RTK_I2C_IC_SLV_REG_LEN
#define BIT_IC_SLV_REG_LEN1(x)              (((x) & BIT_MASK_IC_SLV_REG_LEN1) << BIT_SHIFT_IC_SLV_REG_LEN1)
#define BIT_SHIFT_IC_SLV_REG_LEN1          	24
#define BIT_MASK_IC_SLV_REG_LEN1          	0xFF
#define BIT_CTRL_IC_SLV_REG_LEN1(x)        	(((x) & BIT_MASK_IC_SLV_REG_LEN1) << BIT_SHIFT_IC_SLV_REG_LEN1)

#define BIT_IC_SLV_REG_LEN2(x)              (((x) & BIT_MASK_IC_SLV_REG_LEN2) << BIT_SHIFT_IC_SLV_REG_LEN2)
#define BIT_SHIFT_IC_SLV_REG_LEN2          	16
#define BIT_MASK_IC_SLV_REG_LEN2          	0xFFFF
#define BIT_CTRL_IC_SLV_REG_LEN2(x)        	(((x) & BIT_MASK_IC_SLV_REG_LEN2) << BIT_SHIFT_IC_SLV_REG_LEN2)

#define BIT_IC_SLV_REG_LEN3(x)              (((x) & BIT_MASK_IC_SLV_REG_LEN3) << BIT_SHIFT_IC_SLV_REG_LEN3)
#define BIT_SHIFT_IC_SLV_REG_LEN3          	8
#define BIT_MASK_IC_SLV_REG_LEN3          	0xFFFFFF
#define BIT_CTRL_IC_SLV_REG_LEN3(x)        	(((x) & BIT_MASK_IC_SLV_REG_LEN3) << BIT_SHIFT_IC_SLV_REG_LEN3)

#define BIT_IC_SLV_REG_LEN4(x)              (((x) & BIT_MASK_IC_SLV_REG_LEN4) << BIT_SHIFT_IC_SLV_REG_LEN4)
#define BIT_SHIFT_IC_SLV_REG_LEN4          	0
#define BIT_MASK_IC_SLV_REG_LEN4          	0xFFFFFFFF
#define BIT_CTRL_IC_SLV_REG_LEN4(x)        	(((x) & BIT_MASK_IC_SLV_REG_LEN4) << BIT_SHIFT_IC_SLV_REG_LEN4)


//2 REG_RTK_I2C_IC_CONFIG
#define BIT_IC_CONFIG_CLK(x)                (((x) & BIT_MASK_IC_CONFIG_CLK) << BIT_SHIFT_IC_CONFIG_CLK)
#define BIT_SHIFT_IC_CONFIG_CLK          	0
#define BIT_MASK_IC_CONFIG_CLK          	0xFFFF
#define BIT_CTRL_IC_CONFIG_CLK(x)        	(((x) & BIT_MASK_IC_CONFIG_CLK) << BIT_SHIFT_IC_CONFIG_CLK)

#define BIT_IC_CONFIG_AUTOPOLL_TIMER(x)				(((x) & BIT_MASK_IC_CONFIG_AUTOPOLL_TIMER) << BIT_SHIFT_IC_CONFIG_AUTOPOLL_TIMER)
#define BIT_SHIFT_IC_CONFIG_AUTOPOLL_TIMER         	16
#define BIT_MASK_IC_CONFIG_AUTOPOLL_TIMER          	0xFFFF
#define BIT_CTRL_IC_CONFIG_AUTOPOLL_TIMER(x)       	(((x) & BIT_MASK_IC_CONFIG_AUTOPOLL_TIMER) << BIT_SHIFT_IC_CONFIG_AUTOPOLL_TIMER)

//2 REG_RTK_I2C_IC_DATA
#define BIT_IC_DATA1(x)                	(((x) & BIT_MASK_IC_DATA1) << BIT_SHIFT_IC_DATA1)
#define BIT_SHIFT_IC_DATA1          	0
#define BIT_MASK_IC_DATA1          		0xFF
#define BIT_CTRL_IC_DATA1(x)        	(((x) & BIT_MASK_IC_DATA1) << BIT_SHIFT_IC_DATA1)

#define BIT_IC_DATA2(x)                	(((x) & BIT_MASK_IC_DATA2) << BIT_SHIFT_IC_DATA2)
#define BIT_SHIFT_IC_DATA2          	8
#define BIT_MASK_IC_DATA2          		0xFF
#define BIT_CTRL_IC_DATA2(x)        	(((x) & BIT_MASK_IC_DATA2) << BIT_SHIFT_IC_DATA2)

#define BIT_IC_DATA3(x)                	(((x) & BIT_MASK_IC_DATA3) << BIT_SHIFT_IC_DATA3)
#define BIT_SHIFT_IC_DATA3          	16
#define BIT_MASK_IC_DATA3          		0xFF
#define BIT_CTRL_IC_DATA3(x)        	(((x) & BIT_MASK_IC_DATA3) << BIT_SHIFT_IC_DATA3)

#define BIT_IC_DATA4(x)                	(((x) & BIT_MASK_IC_DATA4) << BIT_SHIFT_IC_DATA4)
#define BIT_SHIFT_IC_DATA4          	24
#define BIT_MASK_IC_DATA4          		0xFF
#define BIT_CTRL_IC_DATA4(x)        	(((x) & BIT_MASK_IC_DATA4) << BIT_SHIFT_IC_DATA4)


#endif //_I2C_BASE_BIT_H_
