#include "HalPrecomp.h" 

#include <pe_fw.h>

#if defined(CONFIG_PE_ENABLE)
//Fetch from DT
static unsigned long pe_fw_virt_addr;
static unsigned long pe_fw_phys_addr;
static unsigned long pe_cpu_virt_addr;
static unsigned long pe_atu_virt_addr;
static unsigned long pe_mem_virt_addr;

unsigned long get_pe_fw_virt_addr(void)
{
	return pe_fw_virt_addr;
}
unsigned long get_pe_fw_phys_addr(void)
{
	return pe_fw_phys_addr;
}
unsigned long get_pe_cpu_virt_addr(void)
{
	return pe_cpu_virt_addr;
}
unsigned long get_pe_atu_virt_addr(void)
{
	return pe_atu_virt_addr;
}
unsigned long get_pe_mem_virt_addr(void)
{
	return pe_mem_virt_addr;
}

void set_pe_fw_virt_addr(unsigned long value)
{
	pe_fw_virt_addr = value;
}
void set_pe_fw_phys_addr(unsigned long value)
{
	pe_fw_phys_addr = value;
}
void set_pe_cpu_virt_addr(unsigned long value)
{
	pe_cpu_virt_addr = value;
}
void set_pe_atu_virt_addr(unsigned long value)
{
	pe_atu_virt_addr = value;
}
void set_pe_mem_virt_addr(unsigned long value)
{
	pe_mem_virt_addr = value;
}

void download_pe_fw(void)
{
	unsigned long pe_atu_virt_addr = get_pe_atu_virt_addr();
	unsigned long pe_mem_virt_addr = get_pe_mem_virt_addr();
	unsigned long pe_cpu_virt_addr = get_pe_cpu_virt_addr();
	unsigned long pe_fw_virt_addr = get_pe_fw_virt_addr();

	panic_printk("[PE_DOWNLOAD] start=======>\r\n");
	
	panic_printk("atu_virt_addr = %x, fw_virt_addr = %x\r\n cpu_virt_addr = %x, mem_virt_addr = %x\r\n", 
		pe_atu_virt_addr, pe_fw_virt_addr, pe_cpu_virt_addr, pe_mem_virt_addr);

	//Change PE boot addr, atu setting
	*(volatile unsigned int*)(pe_atu_virt_addr + 0x4) = 0x00001FC0;
	*(volatile unsigned int*)(pe_atu_virt_addr + 0x8) = 0x0000FFF0;
	*(volatile unsigned int*)(pe_atu_virt_addr + 0xC) = ((get_pe_fw_phys_addr() & 0x0FFFFFFF) >> 16);
	*(volatile unsigned int*)(pe_atu_virt_addr + 0x10) = 0x02000000;
	*(volatile unsigned int*)(pe_atu_virt_addr + 0x14) = 0x00000000;
	*(volatile unsigned int*)(pe_atu_virt_addr + 0x18) = 0x00000000;
	*(volatile unsigned int*)(pe_atu_virt_addr + 0x1C) = 0x00000000;
	*(volatile unsigned int*)(pe_atu_virt_addr + 0x0) = 0x80000000;
	*(volatile unsigned int*)(pe_atu_virt_addr + 0x0) = 0x00000001;

	//Set PE IMEM 64KB/DMEM 32KB
	*(volatile unsigned int*)(pe_mem_virt_addr) = 0x12;
	//Set PE IMEM 32KB/DMEM 64KB
	//*(volatile unsigned int*)(pe_mem_virt_addr) = 0x14;
	panic_printk("Set PE IMEM/DMEM value = %x \r\n", *(unsigned int*)(pe_mem_virt_addr));
	
	//Hold CPU
	*(volatile unsigned int*)(pe_cpu_virt_addr + 0xC) |= 0x00100000;
	panic_printk("Hold CPU, value = %x \r\n", *(volatile unsigned int*)(pe_cpu_virt_addr + 0xC));

	//MEMCPY
	HAL_memset(pe_fw_virt_addr, 0 , 0x900000);
	HAL_memcpy(pe_fw_virt_addr ,data_wfo_rtl8192cd_start,((unsigned int)data_wfo_rtl8192cd_end - (unsigned int)data_wfo_rtl8192cd_start) + 4);

	
	//__cpuc_flush_dcache_area((unsigned long)(pe_fw_virt_addr), 0x900000);
	
	panic_printk("data_wfo_rtl8192cd_start = %x\r\n", data_wfo_rtl8192cd_start);
	panic_printk("data_wfo_rtl8192cd_end = %x\r\n", data_wfo_rtl8192cd_end);
	panic_printk("PE FW size = %d\r\n", (data_wfo_rtl8192cd_end - data_wfo_rtl8192cd_start));
	
	//Reset CPU
	*(volatile unsigned int*)(pe_cpu_virt_addr + 0xC) &= ~0x00100000;
	panic_printk("Reset CPU, value = %x \r\n", *(volatile unsigned int*)(pe_cpu_virt_addr + 0xC));
	panic_printk("[PE_DOWNLOAD] <=======end\r\n");

}

unsigned char check_pe_ready(struct rtl8192cd_priv *priv)
{

	unsigned char pe_ready = RTL_R8(0x1C6);

	return pe_ready;
}

#endif

