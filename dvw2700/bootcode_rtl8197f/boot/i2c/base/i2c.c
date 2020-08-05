#include "dw_i2c.h"

#define I2C_ERROR -1
#define printf prom_printf


#define BSP_SYS_CLK_RATE                (200000000)     //HS1 clock : 200 MHz
#define BSP_DIVISOR         200

#define BSP_TC_BASE         0xB8003100
#define BSP_TC0CNT          (BSP_TC_BASE + 0x08)

#define CYGNUM_HAL_RTC_NUMERATOR 1000000000
#define CYGNUM_HAL_RTC_DENOMINATOR 100
#define CYGNUM_HAL_RTC_DIV_FACTOR BSP_DIVISOR
#define CYGNUM_HAL_RTC_PERIOD ((BSP_SYS_CLK_RATE / CYGNUM_HAL_RTC_DIV_FACTOR) / CYGNUM_HAL_RTC_DENOMINATOR)
#define rtlRegRead(addr)        \
        (*(volatile u32 *)(addr))

#define rtlRegWrite(addr, val)  \
        ((*(volatile u32 *)(addr)) = (val))
        
#define HAL_CLOCK_READ( _pvalue_ )                                      \
{                                                                       \
        *(_pvalue_) = rtlRegRead(BSP_TC0CNT);                                \
        *(_pvalue_) = (rtlRegRead(BSP_TC0CNT) >> 4) & 0x0fffffff;            \
}

void hal_delay_us(int us)
{
    unsigned int val1, val2;
    int diff;
    long usticks;
    long ticks;

    // Calculate the number of counter register ticks per microsecond.

    usticks = (CYGNUM_HAL_RTC_PERIOD * CYGNUM_HAL_RTC_DENOMINATOR) / 1000000;

    // Make sure that the value is not zero. This will only happen if the
    // CPU is running at < 2MHz.
    if( usticks == 0 ) usticks = 1;

    while( us > 0 )
    {
        int us1 = us;

        // Wait in bursts of less than 10000us to avoid any overflow
        // problems in the multiply.
        if( us1 > 10000 )
            us1 = 10000;

        us -= us1;

        ticks = us1 * usticks;

        HAL_CLOCK_READ(&val1);
        while (ticks > 0) {
            do {
                HAL_CLOCK_READ(&val2);
            } while (val1 == val2);
            diff = val2 - val1;
            if (diff < 0) diff += CYGNUM_HAL_RTC_PERIOD;
            ticks -= diff;
            val1 = val2;
        }
    }
}

#define udelay hal_delay_us

void i2c_write_byte(u8 bus, u8 addr, u8 data)
{
	u8 msgbuf[1];
	u8 result;
		
	//msgbuf[0] = subaddr;
	msgbuf[0] = data;
	
	dw_i2c_send_master(bus, addr, msgbuf, 2);
  
}

void i2c_write_byte_slave(u8 data)
{
	u8 msgbuf[1];
	u8 result;
	
	//msgbuf[0] = 0;
	msgbuf[0] = data;
	
	dw_i2c_send_slave(0, 0, msgbuf, 1);
  
}


int i2c_read_byte(u8 bus, u8 addr)
{
	u8 msgbuf[1];
	int result;
	
	//msgbuf[0] = subaddr;
	
	dw_i2c_send_master(bus, addr, msgbuf, 1);
	result = dw_i2c_read_master(bus, addr, msgbuf, 1);
	
	if(result != I2C_ERROR)
	{
		result = msgbuf[0];	
	}
	
	return result;
	
}

int i2c_read_byte_slave()
{
	u8 msgbuf[1];
	int result;
	
	//msgbuf[0] = subaddr;
	
	//dw_i2c_send(bus, addr, msgbuf, 1);
	result = dw_i2c_read_slave(0, 0, &msgbuf, 1);
	
	if(result != I2C_ERROR)
	{
		result = msgbuf[0];	
	}
	
	return result;
	
}

void i2c_write_multi_byte(u8 bus, u8 addr, u8 subaddr, u8 *data, int size)
{
	u8 msgbuf[size+1];
	
	msgbuf[0] = subaddr;
	memcpy(msgbuf+1, data, size);
		
	dw_i2c_send_master(bus, addr, msgbuf, size+1);
	
	//udelay(40000);
	//udelay(40000);
}

int i2c_read_multi_byte(u8 bus, u8 addr, u8 subaddr, u8 *data, int size)
{
	u8 msgbuf[1];
	int result;
	
	msgbuf[0] = subaddr;
	
	dw_i2c_send_master(bus, addr, msgbuf, 1);
	
	result = dw_i2c_read_master(bus, addr, data, size);	
	//udelay(40000);
	//udelay(40000);
	
	return result;
}

void i2c_write_multi_byte_slave(u8 *data, int size)
{
	u8 *msgbuf;
	int result;
	int i;

	//memset(msgbuf, 0, sizeof(msgbuf) );
	//memcpy(msgbuf, data, size);
	msgbuf = data;
	
	/*for(i = 0; i < size; i++)
	{
		dw_i2c_send_slave(0, 0, msgbuf[i], 1);
		//printf("w %d\n",msgbuf[i]);
		hal_delay_us(1);
	}*/
	dw_i2c_send_slave(0, 0, msgbuf, size);
}


