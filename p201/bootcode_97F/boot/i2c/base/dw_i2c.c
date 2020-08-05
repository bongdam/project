#include "dw_i2c.h"
#include "i2c/basic_types.h"
#include "i2c/diag.h"

//#include "rand.h"
//#include "section_config.h"
#include "dw_i2c_base_test.h"
//#include "rtl_utility.h"
#include "i2c/peripheral.h"
//#include "common.h"
#include <linux/interrupt.h>

#ifndef REG32
#define REG32(reg)      (*(volatile unsigned int*)(reg))
#endif


#define BSP_IRR3            0xB8003014
#define GIMR_REG			0xB8003000

#define I2C_ERROR -1
#define printf prom_printf
#define rtlRegRead(addr)        \
        (*(volatile u32 *)(addr))

#define rtlRegWrite(addr, val)  \
        ((*(volatile u32 *)(addr)) = (val))

#define BSP_CLK_MANAGE1 0xB8000010
#define BSP_CLK_MANAGE2 0xB8000014
#define BSP_PIN_MUX_SEL2 0xB8000808

#define I2C_IRQ_NO	30	//GIMR 30	

HAL_DW_I2C_ADAPTER TestI2CMaster;
HAL_DW_I2C_ADAPTER TestI2CSlave;

HAL_DW_I2C_DAT_ADAPTER TestI2CMasterDat;
HAL_DW_I2C_DAT_ADAPTER TestI2CSlaveDat;
HAL_DW_I2C_OP HalI2COp;

volatile u8  I2CVeriDatDes;



static void I2C0IrqHandle(int irqnr, void *dev_id, struct pt_regs *regs)
{
    PHAL_DW_I2C_ADAPTER pHalI2CAdapter = &TestI2CSlave;
    PHAL_DW_I2C_DAT_ADAPTER pI2CAdapterIrq0 = (PHAL_DW_I2C_DAT_ADAPTER)pHalI2CAdapter->pI2CIrqDat;
    //printf("I2C interrupt !!!!!!!!!!!!!!!!!!\n");
    u8  I2CIdx  = pI2CAdapterIrq0->Idx;

    if (HAL_I2C_READ32(I2CIdx,REG_DW_I2C_IC_INTR_STAT) & BIT_CTRL_IC_INTR_STAT_R_GEN_CALL(1))
    {
        printf("I2C%d INTR_GEN_CALL\n",I2CIdx);
        pI2CAdapterIrq0->IC_Intr_Clr = REG_DW_I2C_IC_CLR_GEN_CALL;
        HalI2CClrIntrDWCommon(pI2CAdapterIrq0);
    }
        
    if (HAL_I2C_READ32(I2CIdx,REG_DW_I2C_IC_INTR_STAT) & BIT_CTRL_IC_INTR_STAT_R_RX_DONE(1))
    {
        //SlaveRXDone = 1;
        printf("I2C%d INTR_RX_DONE\n",I2CIdx);
        //printf("I2C%d IC_RXFLR:%2x\n",I2CIdx,HAL_I2C_READ32(I2CIdx,REG_DW_I2C_IC_RXFLR));
        
        pI2CAdapterIrq0->IC_Intr_Clr = REG_DW_I2C_IC_CLR_RX_DONE;
        HalI2CClrIntrDWCommon(pI2CAdapterIrq0);
        
    }
    
    if (HAL_I2C_READ32(I2CIdx,REG_DW_I2C_IC_INTR_STAT) & BIT_CTRL_IC_INTR_STAT_R_TX_ABRT(1))
    {
        printf("!!!I2C%d INTR_TX_ABRT!!!\n",I2CIdx);
        printf("I2C%d IC_TX_ABRT_SOURCE[%2x]: %x\n", I2CIdx, REG_DW_I2C_IC_TX_ABRT_SOURCE, 
                                        HAL_I2C_READ32(I2CIdx,REG_DW_I2C_IC_TX_ABRT_SOURCE));
        pI2CAdapterIrq0->IC_Intr_Clr = REG_DW_I2C_IC_CLR_TX_ABRT;
        HalI2CClrIntrDWCommon(pI2CAdapterIrq0);
    }

    if (HAL_I2C_READ32(I2CIdx,REG_DW_I2C_IC_INTR_STAT) & BIT_CTRL_IC_INTR_STAT_R_RD_REQ(1))
    {          
        //4 Check if the DMA is enabled.
        //4 ->Enabled: to do DMA operation (Enable slave DMA and GDMA channel 1 for TX)
        //4 ->Disabled: to do FIFO write by self
        if (pI2CAdapterIrq0->DMAEn == BIT_CTRL_IC_DMA_CR_TDMAE(1))
        {
        	printf("I2C%d INTR_RD_REQ_DMA_enable\n",I2CIdx);
            pHalI2CAdapter->pI2CIrqOp->HalI2CEnableDMA(pI2CAdapterIrq0);
        }
        else
        {
        	u32 dataLen = pI2CAdapterIrq0->DatLen;
        	pI2CAdapterIrq0->Idx = I2C0_SEL;
			pI2CAdapterIrq0->RWCmd = 0;
			//pI2CAdapterIrq0->DatLen = 1;	//only 1 byte
			HalI2CDATWriteDWCommon(pI2CAdapterIrq0);
			//printf("I2C0 data sending = %x\n", *pI2CAdapterIrq0->RWDat);
			pI2CAdapterIrq0->RWDat = NULL;
            //pI2CAdapterIrq0->RWDat++;
        }
        
        pI2CAdapterIrq0->IC_Intr_Clr = REG_DW_I2C_IC_CLR_RD_REQ;
        HalI2CClrIntrDWCommon(pI2CAdapterIrq0);
    } 

    if (HAL_I2C_READ32(I2CIdx,REG_DW_I2C_IC_INTR_STAT) & BIT_CTRL_IC_INTR_STAT_R_TX_EMPTY(1))
    {
        printf("!!!I2C%d INTR_TX_EMPTY!!!\n",I2CIdx);
    }

    if (HAL_I2C_READ32(I2CIdx,REG_DW_I2C_IC_INTR_STAT) & BIT_CTRL_IC_INTR_STAT_R_TX_OVER(1))
    {
        printf("!!!I2C%d INTR_TX_OVER!!!\n",I2CIdx);
        pI2CAdapterIrq0->IC_Intr_Clr = REG_DW_I2C_IC_CLR_TX_OVER;
        HalI2CClrIntrDWCommon(pI2CAdapterIrq0);
    }

    if (HAL_I2C_READ32(I2CIdx,REG_DW_I2C_IC_INTR_STAT) & BIT_CTRL_IC_INTR_STAT_R_RX_OVER(1))
    {   
        printf("I2C%d INTR_RX_OVER\n",I2CIdx);
        pI2CAdapterIrq0->IC_Intr_Clr = REG_DW_I2C_IC_CLR_RX_OVER;
        HalI2CClrIntrDWCommon(pI2CAdapterIrq0);
    }

    if (HAL_I2C_READ32(I2CIdx,REG_DW_I2C_IC_INTR_STAT) & BIT_CTRL_IC_INTR_STAT_R_RX_FULL(1))
    {
    	printf("!!!I2C%d INTR_RX_FULL!!!\n",I2CIdx);
        while(HAL_I2C_READ32(pI2CAdapterIrq0->Idx,REG_DW_I2C_IC_STATUS) & BIT_CTRL_IC_STATUS_RFNE(1))
        {
                I2CVeriDatDes = pHalI2CAdapter->pI2CIrqOp->HalI2CDATRead(pI2CAdapterIrq0);
				printf("I2CVeriCntRd, data=%s\n",I2CVeriDatDes);
        }
    }
    
    if (HAL_I2C_READ32(I2CIdx,REG_DW_I2C_IC_INTR_STAT) & BIT_CTRL_IC_INTR_STAT_R_RX_UNDER(1))
    {
       printf("!!!I2C%d INTR_RX_UNDER!!!\n",I2CIdx);
        pI2CAdapterIrq0->IC_Intr_Clr = REG_DW_I2C_IC_CLR_RX_UNDER;
        HalI2CClrIntrDWCommon(pI2CAdapterIrq0);
    }
}

struct irqaction irq_I2C = {I2C0IrqHandle, (unsigned long)NULL, (unsigned long)I2C_IRQ_NO, "I2C", (void *)NULL, (struct irqaction *)NULL};

static inline u32 rtlRegMask(u32 addr, u32 mask, u32 value)
{
        u32 reg;

        reg = rtlRegRead(addr);
        reg &= ~mask;
        reg |= value & mask;
        rtlRegWrite(addr, reg);
        reg = rtlRegRead(addr); /* flush write to the hardware */

        return reg;
}

void dw_i2c_end_master()
{
	PHAL_DW_I2C_ADAPTER pI2CAdapterMtr = &TestI2CMaster;
	PHAL_DW_I2C_DAT_ADAPTER pI2CDatAdapterMtr = (PHAL_DW_I2C_DAT_ADAPTER)pI2CAdapterMtr->pI2CIrqDat;
	
	while(!(HAL_I2C_READ32(pI2CDatAdapterMtr->Idx,REG_DW_I2C_IC_RAW_INTR_STAT) & BIT_CTRL_IC_RAW_INTR_STAT_STOP_DET(1)));

	pI2CDatAdapterMtr->IC_INRT_MSK = 0;
	pI2CAdapterMtr->pI2CIrqOp->HalI2CEnableIntr(pI2CDatAdapterMtr);
	pI2CDatAdapterMtr->ModulEn = 0;
	pI2CAdapterMtr->pI2CIrqOp->HalI2CModuleEn(pI2CDatAdapterMtr);
}

void dw_i2c_end_slave()
{
	PHAL_DW_I2C_ADAPTER pI2CAdapterSlv = &TestI2CSlave;
	PHAL_DW_I2C_DAT_ADAPTER pI2CDatAdapterSlv = (PHAL_DW_I2C_DAT_ADAPTER)pI2CAdapterSlv->pI2CIrqDat;
	
	while(!(HAL_I2C_READ32(pI2CDatAdapterSlv->Idx,REG_DW_I2C_IC_RAW_INTR_STAT) & BIT_CTRL_IC_RAW_INTR_STAT_STOP_DET(1)));

	pI2CDatAdapterSlv->IC_INRT_MSK = 0;
	pI2CAdapterSlv->pI2CIrqOp->HalI2CEnableIntr(pI2CDatAdapterSlv);
	pI2CDatAdapterSlv->ModulEn = 0;
	pI2CAdapterSlv->pI2CIrqOp->HalI2CModuleEn(pI2CDatAdapterSlv);
}

// I2CMtr need data
void dw_i2c_send_master(u8 bus, u8 addr, u8 data[], int num)
{
	u32 I2CVeriCnt;
	
	PHAL_DW_I2C_ADAPTER pI2CAdapterMtr = &TestI2CMaster;
	
	PHAL_DW_I2C_DAT_ADAPTER pI2CDatAdapterMtr = (PHAL_DW_I2C_DAT_ADAPTER)pI2CAdapterMtr->pI2CIrqDat;
	
	while (!(HAL_I2C_READ32(pI2CDatAdapterMtr->Idx,REG_DW_I2C_IC_STATUS) & BIT_CTRL_IC_STATUS_TFE(1)));
		
	pI2CDatAdapterMtr->Idx = bus;
	pI2CDatAdapterMtr->TSarAddr= addr;
	
	pI2CDatAdapterMtr->RWCmd = 0;
	
	dw_i2c_init_master(pI2CAdapterMtr);
	
	pI2CDatAdapterMtr->RWDat = data;//[I2CVeriCnt];
	pI2CDatAdapterMtr->DatLen = num;
	pI2CAdapterMtr->pI2CIrqOp->HalI2CDATWrite(pI2CDatAdapterMtr); 

	dw_i2c_end_master();
	
	  
}

void dw_i2c_send_slave(u8 bus, u8 addr, u8 data[], int num)
{
	u32 I2CVeriCnt;
	
	PHAL_DW_I2C_ADAPTER pI2CAdapterSlv = &TestI2CSlave;
	
	PHAL_DW_I2C_DAT_ADAPTER pI2CDatAdapterSlv = (PHAL_DW_I2C_DAT_ADAPTER)pI2CAdapterSlv->pI2CIrqDat;
	
	//if (HAL_I2C_READ32(pI2CDatAdapterSlv->Idx,REG_DW_I2C_IC_RAW_INTR_STAT) & BIT_CTRL_IC_INTR_STAT_R_RD_REQ(1))
	{
		pI2CDatAdapterSlv->Idx = bus;
	
		pI2CDatAdapterSlv->RWCmd = 0;
		
		//dw_i2c_init_slave(pI2CAdapterSlv);
		
		//pI2CDatAdapterSlv->RWDat[0] = data[0];//[I2CVeriCnt];

		memcpy(pI2CDatAdapterSlv->RWDat, data, num);	//test 0320
        //printf("data= %02X %02X %02X %02X\n", data[0],data[1],data[2],data[3]);	//test 0320
		
		pI2CDatAdapterSlv->DatLen = num;
		//pI2CAdapterSlv->pI2CIrqOp->HalI2CDATWrite(pI2CDatAdapterSlv); 
	  
		//pI2CDatAdapterSlv->IC_Intr_Clr = REG_DW_I2C_IC_CLR_RD_REQ;
		//pI2CAdapterSlv->pI2CIrqOp->HalI2CClrIntr(pI2CDatAdapterSlv);

		//dw_i2c_end_slave();
  
	}
	  
}

int dw_i2c_read_master(u8 bus, u8 addr, u8 data[], int num)
{
		u32 I2CVeriCnt;
	
		PHAL_DW_I2C_ADAPTER pI2CAdapterMtr = &TestI2CMaster;	
		
		PHAL_DW_I2C_DAT_ADAPTER pI2CDatAdapterMtr = (PHAL_DW_I2C_DAT_ADAPTER)pI2CAdapterMtr->pI2CIrqDat;
		
		while (!(HAL_I2C_READ32(pI2CDatAdapterMtr->Idx,REG_DW_I2C_IC_STATUS) & BIT_CTRL_IC_STATUS_TFE(1)));
		
		pI2CDatAdapterMtr->Idx = bus;
		pI2CDatAdapterMtr->TSarAddr= addr;
		
		u32 I2CVeriCntRd = 0;
		u32 I2CTimeOutCnt = 0;
		
		pI2CDatAdapterMtr->RWCmd = 1;
		pI2CDatAdapterMtr->RWDat = data;
				
		dw_i2c_init_master(pI2CAdapterMtr);
		
		//for (I2CVeriCnt= 0; I2CVeriCnt < num; I2CVeriCnt++)
		{
			pI2CDatAdapterMtr->DatLen = num;
		    pI2CAdapterMtr->pI2CIrqOp->HalI2CDATWrite(pI2CDatAdapterMtr);
		    
		    while(!(HAL_I2C_READ32(pI2CDatAdapterMtr->Idx,REG_DW_I2C_IC_RAW_INTR_STAT) & BIT_CTRL_IC_RAW_INTR_STAT_STOP_DET(1)));    
	  	}
    
	    for (;I2CVeriCntRd<num;)
	    {
	    	//udelay(1000);  	
#if 1            
					//printf("I2C_VERI_TIMEOUT_CNT= %x\n", I2C_VERI_TIMEOUT_CNT);

	        //to deal with transmittion error
	        if (I2CTimeOutCnt++ > (10*I2C_VERI_TIMEOUT_CNT))
	        {
	              printf("     **** Timeout Error ****\n\n");

	              //I2CErrFlag = _TRUE;
	              //break;
	              
	                            
	              return I2C_ERROR;
	        }
#endif
	        if (HAL_I2C_READ32(pI2CDatAdapterMtr->Idx,REG_DW_I2C_IC_STATUS) & BIT_CTRL_IC_STATUS_RFNE(1))
	        {
	              I2CTimeOutCnt = 0;
	              data[I2CVeriCntRd] = pI2CAdapterMtr->pI2CIrqOp->HalI2CDATRead(pI2CDatAdapterMtr);//HalI2CDATRead(pI2CDatAdapterMtr);
	                           
	              I2CVeriCntRd++;                              
	        }
	    }
    
    dw_i2c_end_master();
    
    return 0;
}

int dw_i2c_read_slave(u8 bus, u8 addr, u8 data[], int num)
{
		u32 I2CVeriCnt;
	
		PHAL_DW_I2C_ADAPTER pI2CAdapterSlv = &TestI2CSlave;	
		
		PHAL_DW_I2C_DAT_ADAPTER pI2CDatAdapterSlv = (PHAL_DW_I2C_DAT_ADAPTER)pI2CAdapterSlv->pI2CIrqDat;
		
		while (!(HAL_I2C_READ32(pI2CDatAdapterSlv->Idx,REG_DW_I2C_IC_STATUS) & BIT_CTRL_IC_STATUS_TFE(1)));
		
		pI2CDatAdapterSlv->Idx = bus;
		
		
		u32 I2CVeriCntRd = 0;
		u32 I2CTimeOutCnt = 0;
				
		//dw_i2c_init_slave(pI2CAdapterSlv);
  
    for (;I2CVeriCntRd<num;)
    {
    	//udelay(1000);
    	
#if 1            
				//printf("I2C_VERI_TIMEOUT_CNT= %x\n", I2C_VERI_TIMEOUT_CNT);

        //to deal with transmittion error
        if (I2CTimeOutCnt++ > (10*I2C_VERI_TIMEOUT_CNT))
        {
              //printf("     **** Timeout Error ****\n\n");

              //I2CErrFlag = _TRUE;
              //break;
              
                            
              return I2C_ERROR;
        }
#endif                
        if (HAL_I2C_READ32(pI2CDatAdapterSlv->Idx,REG_DW_I2C_IC_STATUS) & BIT_CTRL_IC_STATUS_RFNE(1))
        {
              I2CTimeOutCnt = 0;
              data[I2CVeriCntRd] = pI2CAdapterSlv->pI2CIrqOp->HalI2CDATRead(pI2CDatAdapterSlv);//HalI2CDATRead(pI2CDatAdapterMtr);
              
                           
              I2CVeriCntRd++;
              
              //if(I2CVeriCntRd < num )
              {
              //	  pI2CDatAdapterMtr->DatLen = 1;
    					//		pI2CAdapterMtr->pI2CIrqOp->HalI2CDATWrite(pI2CDatAdapterMtr);
    					//		while(!(HAL_I2C_READ32(pI2CDatAdapterMtr->Idx,REG_DW_I2C_IC_RAW_INTR_STAT) & BIT_CTRL_IC_RAW_INTR_STAT_STOP_DET(1)));    
              }
              
                    
        }
    }
    
    //dw_i2c_end_slave();
    
    return 0;
}

static void i2c_hw_init_master()
{
	/*
        * Reg: 0x010
        * Set: [9]=1, [11]=1, [31]=1
        * Description: I2C Enable
        */
        rtlRegMask(BSP_CLK_MANAGE1, 1<<9 | 1<<11 | 1<<31, 1 << 9 | 1<<11 | 1<<31);

        /*
        * Reg:0x014
        * Set: [4]=1, [8]=1, [10]=1, [12]=1
        * Description: I2C Enable
        */
        rtlRegMask(BSP_CLK_MANAGE2, 1<<4 | 1<<8 | 1<<10 | 1<<12, 1<<4 | 1<<8 | 1<<10 | 1<<12);

	/*
        * Reg: 0x808
        * Set: PIN_MUX_SEL2[23:20](TXCTL)=4, PIN_MUX_SEL2[15:12](RXCTL)=5
        * Description: PIN_MUX_SEL2[23:20], PIN_MUX_SEL2[15:12] For I2C0.
        */
        rtlRegMask(BSP_PIN_MUX_SEL2, 0xF<<20 | 0xF<<12, 4<<20 | 5<<12);

}

static void i2c_hw_init_slave()
{
	/*
        * Reg: 0x010
        * Set: [9]=1, [11]=1, [31]=1
        * Description: I2C Enable
        */
        rtlRegMask(BSP_CLK_MANAGE1, 1<<9 | 1<<11 | 1<<31, 1 << 9 | 1<<11 | 1<<31);
        
  /*
        * Reg:0x014
        * Set: [4]=1, [8]=1, [10]=1, [12]=1
        * Description: I2C Enable
        */
        rtlRegMask(BSP_CLK_MANAGE2, 1<<4 | 1<<8 | 1<<10 | 1<<12, 1<<4 | 1<<8 | 1<<10 | 1<<12);
	
	/*
        * Reg: 0x808
        * Set: PIN_MUX_SEL2[27:24](TXC)=6, PIN_MUX_SEL2[15:12](RXCTL)=5
        * Description: PIN_MUX_SEL2[27:24], PIN_MUX_SEL2[15:12] For I2C0_SLV.
        */
        rtlRegMask(BSP_PIN_MUX_SEL2, 0xF<<24 | 0xF<<12, 6<<24 | 5<<12);

}



int dw_i2c_init_master()
{
	PHAL_DW_I2C_ADAPTER pI2CAdapterMtr = &TestI2CMaster;
	PHAL_DW_I2C_DAT_ADAPTER pI2CDatAdapterMtr = (PHAL_DW_I2C_DAT_ADAPTER)pI2CAdapterMtr->pI2CIrqDat;
	
	s8  I2CVeriAddrMod = ADDR_7BIT;
	u8  I2CVeriSpdMod = SS_MODE;
	
	while (HAL_I2C_READ32(pI2CDatAdapterMtr->Idx,REG_DW_I2C_IC_STATUS) & BIT_CTRL_IC_STATUS_ACTIVITY(1));
	
	
	pI2CDatAdapterMtr->IC_INRT_MSK = 0x0;
  	pI2CAdapterMtr->pI2CIrqOp->HalI2CEnableIntr(pI2CDatAdapterMtr);
	pI2CDatAdapterMtr->ModulEn = 0;
	pI2CAdapterMtr->pI2CIrqOp->HalI2CModuleEn(pI2CDatAdapterMtr);
	
	
	pI2CDatAdapterMtr->AddrMd = I2CVeriAddrMod;
	pI2CDatAdapterMtr->SpdMd = I2CVeriSpdMod;
	
	pI2CDatAdapterMtr->SDAHd = 1;//mini value:1
	pI2CDatAdapterMtr->SpdMd = I2CVeriSpdMod;
 	switch (I2CVeriSpdMod)
	{
		case SS_MODE:
			pI2CDatAdapterMtr->SpdHz = 100;
			break;
			
		case FS_MODE:
			pI2CDatAdapterMtr->SpdHz = 400;
			break; 

		case HS_MODE:
			pI2CDatAdapterMtr->SpdHz = 400;
			break; 
			
		default:
			break;
	}
		
	
	//4 RESTART MUST be set in these condition in Master mode. 
	//4 But it might be NOT compatible in old slaves.
	if ((I2CVeriAddrMod == ADDR_10BIT) || (I2CVeriSpdMod==HS_MODE))
		pI2CDatAdapterMtr->ReSTR = 1;
	
	i2c_hw_init_master();
	
	pI2CAdapterMtr->pI2CIrqOp->HalI2CInitMaster(pI2CDatAdapterMtr);
	pI2CAdapterMtr->pI2CIrqOp->HalI2CSetCLK(pI2CDatAdapterMtr);
  
	pI2CDatAdapterMtr->IC_INRT_MSK = 0 ;
	pI2CAdapterMtr->pI2CIrqOp->HalI2CEnableIntr(pI2CDatAdapterMtr);
	pI2CDatAdapterMtr->ModulEn = 1;
	pI2CAdapterMtr->pI2CIrqOp->HalI2CModuleEn(pI2CDatAdapterMtr);

	pI2CAdapterMtr->pI2CIrqOp->HalI2CClrAllIntr(pI2CDatAdapterMtr);

	return 0;
	
}

int dw_i2c_init_slave()
{
	PHAL_DW_I2C_ADAPTER pI2CAdapterSlv = &TestI2CSlave;
	PHAL_DW_I2C_DAT_ADAPTER pI2CDatAdapterSlv = (PHAL_DW_I2C_DAT_ADAPTER)pI2CAdapterSlv->pI2CIrqDat;
	
	s8  I2CVeriAddrMod = ADDR_7BIT;
	u8  I2CVeriSpdMod = SS_MODE;
	
	while (HAL_I2C_READ32(pI2CDatAdapterSlv->Idx,REG_DW_I2C_IC_STATUS) & BIT_CTRL_IC_STATUS_ACTIVITY(1));
	
	
	pI2CDatAdapterSlv->IC_INRT_MSK = 0x0;
  	pI2CAdapterSlv->pI2CIrqOp->HalI2CEnableIntr(pI2CDatAdapterSlv);
	pI2CDatAdapterSlv->ModulEn = 0;
	pI2CAdapterSlv->pI2CIrqOp->HalI2CModuleEn(pI2CDatAdapterSlv);
	
	
	pI2CDatAdapterSlv->AddrMd = I2CVeriAddrMod;
	
	pI2CDatAdapterSlv->SDAHd = 40;//7;//mini value:7
	pI2CDatAdapterSlv->SpdMd = I2CVeriSpdMod;

	//4 RESTART MUST be set in these condition in Master mode. 
	//4 But it might be NOT compatible in old slaves.
	if ((I2CVeriAddrMod == ADDR_10BIT) || (I2CVeriSpdMod==HS_MODE))
		pI2CDatAdapterSlv->ReSTR = 1;

	i2c_hw_init_slave();

	REG32(GIMR_REG) |= (1<<30);
	REG32(BSP_IRR3) |= (3<<24);
	request_IRQ(I2C_IRQ_NO, &irq_I2C, NULL);

	
	pI2CAdapterSlv->pI2CIrqOp->HalI2CInitSlave(pI2CDatAdapterSlv);
			
	pI2CDatAdapterSlv->IC_INRT_MSK = BIT_CTRL_IC_INTR_MASK_M_RD_REQ(1); //0x0;
	pI2CAdapterSlv->pI2CIrqOp->HalI2CEnableIntr(pI2CDatAdapterSlv);
	pI2CDatAdapterSlv->ModulEn = 1;
	pI2CAdapterSlv->pI2CIrqOp->HalI2CModuleEn(pI2CDatAdapterSlv);

	pI2CAdapterSlv->pI2CIrqOp->HalI2CClrAllIntr(pI2CDatAdapterSlv);



  	return 0;
	
}


int dw_i2c_probe(void)
{
	PHAL_DW_I2C_OP pHalI2COp = (PHAL_DW_I2C_OP)&HalI2COp;

	PHAL_DW_I2C_DAT_ADAPTER pI2CDatAdapterMtr = &TestI2CMasterDat;
	PHAL_DW_I2C_DAT_ADAPTER pI2CDatAdapterSlv = &TestI2CSlaveDat;
	
	//PI2C_VERI_PARA pI2CVeriPara = (PI2C_VERI_PARA) I2CTestData;
	
	PHAL_DW_I2C_ADAPTER pI2CAdapterMtr = &TestI2CMaster;
	PHAL_DW_I2C_ADAPTER pI2CAdapterSlv = &TestI2CSlave;
	
	HalI2COpInit(pHalI2COp);
	
	#ifdef CONFIG_I2C_MASTER
  // Master setting
  	pI2CDatAdapterMtr->Idx = 0;
  	pI2CDatAdapterMtr->ICClk = SYSTEM_CLK/1000000;
    pI2CDatAdapterMtr->Master = 1;
    pI2CDatAdapterMtr->ModulEn = 1;
  
    pI2CDatAdapterMtr->Spec = 0;
    pI2CDatAdapterMtr->GC_STR = 0;//0 for using GC
    pI2CAdapterMtr->pI2CIrqOp = (PHAL_DW_I2C_OP)pHalI2COp;
    pI2CAdapterMtr->pI2CIrqDat = (PHAL_DW_I2C_DAT_ADAPTER)pI2CDatAdapterMtr;
    
    dw_i2c_init_master(pI2CAdapterMtr);
	#endif

	#ifdef CONFIG_I2C_SLAVE
	// Slave setting
	pI2CDatAdapterSlv->Idx = 0;
	pI2CDatAdapterSlv->Master = 0;
	pI2CDatAdapterSlv->ModulEn = 1;
	pI2CDatAdapterSlv->TSarAddr= I2C0_ADDR;
	pI2CDatAdapterSlv->GC_STR = 1;//enable GC ack or not, 1 for enable
	pI2CAdapterSlv->pI2CIrqOp = (PHAL_DW_I2C_OP)pHalI2COp;
	pI2CAdapterSlv->pI2CIrqDat = (PHAL_DW_I2C_DAT_ADAPTER)pI2CDatAdapterSlv;

	dw_i2c_init_slave(pI2CAdapterSlv);
	#endif

	return 0;
}
