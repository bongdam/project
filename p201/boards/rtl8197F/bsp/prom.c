/*
 * Realtek Semiconductor Corp.
 *
 * bsp/prom.c
 *     bsp early initialization code
 *
 * Copyright (C) 2006-2012 Tony Wu (tonywu@realtek.com)
 */
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <asm/addrspace.h>
#include <asm/bootinfo.h>

#ifdef CONFIG_RTL_DEBUG_COUNTER
#include <linux/rtl_debug.h>
#endif
#include "bspcpu.h"
#include "bspchip.h"

unsigned int bsp_uart0_rbr=BSP_UART0_RBR_8197F, bsp_uart0_thr=BSP_UART0_THR_8197F;

extern char arcs_cmdline[];

#ifdef CONFIG_PARAM_PASSING
static char **prom_envp;
#ifdef CONFIG_BLK_DEV_INITRD
extern unsigned long initrd_start, initrd_end;
#endif
#endif

#ifdef CONFIG_EARLY_PRINTK
static int promcons_output __initdata = 0;

void unregister_prom_console(void)
{
	if (promcons_output)
		promcons_output = 0;
}

void disable_early_printk(void)
    __attribute__ ((alias("unregister_prom_console")));

void prom_putchar(char c)
{
	unsigned int busy_cnt = 0;

	do
	{
		/* Prevent Hanging */
		if (busy_cnt++ >= 30000)
		{
			/* Reset Tx FIFO */
			REG8(BSP_UART0_FCR) = BSP_TXRST | BSP_CHAR_TRIGGER_14;
			return;
		}
	} while ((REG8(BSP_UART0_LSR) & BSP_LSR_THRE) == BSP_TxCHAR_AVAIL);

	/* Send Character */
	REG8(BSP_UART0_THR) = c;
	return;
}

static int bsp_serial_init(void)
{
	if (IS_8197F_VG()) {
		bsp_uart0_rbr = BSP_UART0_RBR_8197F_VG;
		bsp_uart0_thr = BSP_UART0_THR_8197F_VG;
	}
	
	REG32(BSP_UART0_IER) = 0;

	REG32(BSP_UART0_LCR) = BSP_LCR_DLAB;
	REG32(BSP_UART0_DLL) = BSP_UART0_BAUD_DIVISOR & 0x00ff;
	REG32(BSP_UART0_DLM) = (BSP_UART0_BAUD_DIVISOR & 0xff00) >> 8;
//REG32(BSP_UART0_SCR) = 0xA0030; // 57600, 115200
//REG32(BSP_UART0_STSR) = 0xC0; // 57600, 115200
	REG32(BSP_UART0_LCR) = BSP_CHAR_LEN_8;
	return 0;
}
#endif

#ifdef CONFIG_PARAM_PASSING
char *prom_getenv(char *envname)
{
	char **env = prom_envp;
	int i;

	i = strlen(envname);

	while (*env) {
		if (strncmp(envname, *env, i) == 0 && *(*env+i) == '=')
			return *env + i + 1;
		env++;
	}

	return 0;
}


static __init void prom_init_cmdline(void)
{
	int argc;
	char **argv;
	int i;
	pr_debug("prom: fw_arg0=%08x fw_arg1=%08x fw_arg2=%08x fw_arg3=%08x\n",
	       (unsigned int)fw_arg0, (unsigned int)fw_arg1,
	       (unsigned int)fw_arg2, (unsigned int)fw_arg3);

	argc = fw_arg0;
	argv = (char **) KSEG1ADDR(fw_arg1);

	if (!argv) {
		pr_debug("argv=%p is invalid, skipping\n",
		       argv);
		return;
	}

	for (i = 0; i < argc; i++) {
		char *p = (char *) KSEG1ADDR(argv[i]);

		if (CPHYSADDR(p) && *p) {
			pr_debug("argv[%d]: %s\n", i, p);
			
			strlcat(arcs_cmdline, " ", sizeof(arcs_cmdline));
			strlcat(arcs_cmdline, p, sizeof(arcs_cmdline));
		}
	}

}
#endif

const char *get_system_type(void)
{
	return "RTL8197F";
}

//void __init bsp_free_prom_memory(void)
void __init prom_free_prom_memory(void) //mips-ori
{
}

/* Do basic initialization */
//void __init bsp_init(void)
void __init prom_init(void) // mips-ori
{
#ifdef CONFIG_PARAM_PASSING
	unsigned char *memsize_str = NULL;
#ifdef CONFIG_BLK_DEV_INITRD
	unsigned char *initrd_start_str = NULL,*initrd_size_str = NULL;
	unsigned long initrd_size;
#endif
#endif
	
	u_long mem_size;

	bsp_serial_init(); // for debug

#ifdef CONFIG_PARAM_PASSING
    fw_init_cmdline();
#if 0
	prom_init_cmdline();

	prom_envp = (char **)fw_arg2;
	/* memory env */
	memsize_str = prom_getenv("memsize");	
	if(memsize_str != NULL)
	{
		mem_size = simple_strtol(memsize_str, NULL, 0);
#ifdef  CONFIG_RTL8198C_OVER_256MB
		mem_size = (256 << 20);
		add_memory_region(0, mem_size, BOOT_MEM_RAM);	
		add_memory_region(0x30000000, 256 * 1024 * 1024, BOOT_MEM_RAM);
#else
		add_memory_region(0, mem_size, BOOT_MEM_RAM);
#endif
	}else{
		/* use orig function */
		switch (REG32(0xB800000C) & 0x0F) {
			case 0x06:
			case 0x0C:
				mem_size =  (32 << 20);
				break;
			case 0x04:
			case 0x0A:
				mem_size =  (64 << 20);
				break;
			case 0x05:
			case 0x0B:
				mem_size =  (128 << 20);
				break;
			default:
				//mem_size = cpu_mem_size;
				mem_size = (REG32(0xB8000F00) << 20);
		}

#ifdef  CONFIG_RTL8198C_OVER_256MB
		mem_size = (256 << 20);
		add_memory_region(0, mem_size, BOOT_MEM_RAM);	
		add_memory_region(0x30000000, 256 * 1024 * 1024, BOOT_MEM_RAM);
		
#else
		//printk("mem_size=%d MB\n", mem_size>>20);
		add_memory_region(0, mem_size, BOOT_MEM_RAM);
#endif
	}

#ifdef CONFIG_BLK_DEV_INITRD
	/* initrd env */
	initrd_start_str = prom_getenv("initrd_start");
	initrd_size_str = prom_getenv("initrd_size");

	if(initrd_start_str != NULL && initrd_size_str != NULL){
		initrd_start=simple_strtol((const char*)(initrd_start_str), (char **)NULL, 16);
		initrd_size=simple_strtol((const char*)(initrd_size_str), (char **)NULL, 16);
		initrd_end = initrd_start + initrd_size;
	}
#endif
#endif
#else

	switch (REG32(0xB800000C) & 0x0F) {
		case 0x06:
		case 0x0C:
			mem_size =  (32 << 20);
			break;
		case 0x04:
		case 0x0A:
			mem_size =  (64 << 20);
			break;
		case 0x05:
		case 0x0B:
			mem_size =  (128 << 20);
			break;
		default:
			//mem_size = cpu_mem_size;
			mem_size = (REG32(0xB8000F00) << 20);
	}

#ifdef  CONFIG_RTL8198C_OVER_256MB
	mem_size = (256 << 20);
	add_memory_region(0, mem_size, BOOT_MEM_RAM);	
	add_memory_region(0x30000000, 256 * 1024 * 1024, BOOT_MEM_RAM);
	
#else
	//printk("mem_size=%lu MB\n", mem_size>>20);
#ifdef CONFIG_RTL_DEBUG_COUNTER
	add_memory_region(0, mem_size-RTL_COUNTER_DEBUG_MEM_SIZE, BOOT_MEM_RAM);
	rtl_set_mem_addr((KSEG1+mem_size-RTL_COUNTER_DEBUG_MEM_SIZE));
#else
	add_memory_region(0, mem_size, BOOT_MEM_RAM);
#endif
#endif //CONFIG_RTL8198C_OVER_256MB

#endif //CONFIG_PARAM_PASSING

#ifndef CONFIG_RTL_819X_SWCORE
        #ifdef CONFIG_RTL_8197F
        #define SYS_CLK_MAG                           (0xB8000000+0x0010)
        #define CM_ACTIVE_SWCORE               (1<<11) 
        #define EPHY_CONTROL                        (0xB8000000+0x01E0)
        #define EN_ROUTER_MODE                       (1<<12)    
        REG32(SYS_CLK_MAG) &= ~CM_ACTIVE_SWCORE;
        REG32(EPHY_CONTROL) &= ~EN_ROUTER_MODE;
        #endif
#endif

}
