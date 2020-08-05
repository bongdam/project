##/*-------------------------------------------------------------------
##		Created by REALTEK  
##--------------------------------------------------------------------*/
include ../.config
#CROSS = mips-linux-

OUTDIR	= ./Output
CC	= $(CROSS)gcc
AS	= $(CROSS)as
AR	= $(CROSS)ar crs
LD	= $(CROSS)ld
OBJCOPY = $(CROSS)objcopy
#OBJCOPY = objcopy

OBJDUMP	= $(CROSS)objdump
IMG2BIN	= $(CROSS)img2bin
NM	= $(CROSS)nm
RM	= rm


TOOLCFLAGS	=
TOOLLDFLAGS	= -n

OPT	=  -G 0

TEXT	=

INCLUDES	= -I../bsp -I. -I./include

CFLAGS	= -march=mips32r2 -g  -fomit-frame-pointer -fno-pic -mno-abicalls $(TOOLCFLAGS) $(OPT) $(INCLUDES)\
          -D__KERNEL__\
          -Dlinux\
          -O 

#CFLAGS += -save-temps
CFLAGS += -gdwarf-2
       
ifeq ($(CONFIG_DHCP_SERVER),y)
CFLAGS += -DDHCP_SERVER
endif
ifeq ($(CONFIG_HTTP_SERVER),y)
CFLAGS += -DHTTP_SERVER
endif
ifeq ($(CONFIG_SUPPORT_TFTP_CLIENT),y)
CFLAGS += -DSUPPORT_TFTP_CLIENT
endif
ifeq ($(CONFIG_NEW_CONSOLE_SUPPORT),y)
CFLAGS += -DCONFIG_NEW_CONSOLE_SUPPORT
endif

ifeq ($(CONFIG_BOOT_DEBUG_ENABLE),y)
CFLAGS += -DCONFIG_BOOT_DEBUG_ENABLE
endif

#------------------------------------------------------------------------------------------
ifneq "$(strip $(JUMP_ADDR))" ""
CFLAGS += -DJUMP_ADDR=$(JUMP_ADDR)
endif

ifeq ($(RTL865X),1)
CFLAGS += -DRTL865X=1 -DCONFIG_RTL865X=y -DCONFIG_RTL865XC=1 
CFLAGSW = $(CFLAGS) -DWRAPPER -DRTL865X
endif

ifeq ($(RTL8198),1)
CFLAGS += -DRTL8198=1 -DCONFIG_RTL865XC=1
CFLAGSW = $(CFLAGS) -DWRAPPER -DRTL8198
endif


#--------------------------------------
ifeq ($(CONFIG_DDR_SDRAM),y)
CFLAGS += -DDDR_SDRAM
endif
ifeq ($(CONFIG_DDR1_SDRAM),y)
CFLAGS += -DDDR1_SDRAM
endif
ifeq ($(CONFIG_DDR2_SDRAM),y)
CFLAGS += -DDDR2_SDRAM
endif
#--------------------------------------
ifeq ($(CONFIG_SW_8366GIGA),y)
CFLAGS += -DSW_8366GIGA
endif



#--------------------------------------

ifeq ($(CONFIG_SPI_STD_MODE),y)
CFLAGS += -DCONFIG_SPI_STD_MODE
endif

ifeq ($(CONFIG_SW_8367R),y)
CFLAGS += -I./rtl8367r/
endif

ifeq ($(CONFIG_SW_83XX),y)
CFLAGS += -I./rtl83xx/
endif

ifeq ($(CONFIG_NAND_FLASH_BOOTING),y)
LDFLAGS = -nostdlib  -T./ld.script_nand  -EL   --static
else
LDFLAGS = -nostdlib  -T./ld.script  -EL   --static
endif
WLDFLAGS = -nostdlib  -T./ldw.script  -EL   --static
ASFLAGS	=  -D__ASSEMBLY__  -x assembler-with-cpp -G 0


CRT	=
LIBS	=

.SUFFIXES : .s .S .c .o .out .nm .img .sr .sre .text .bin .scr

all:
ifeq (,$(wildcard ./asm/Makefile))
	@echo ""
else
	make -C asm clean
	make -C asm HUAWEI=n RTL_BOOTCODE=y
	sync;sync;sync;
	cp -f ./asm/rtl_wrapper.s ./init/rtl_wrapper.S
endif

clean:
ifeq (,$(wildcard ./asm/Makefile))
	@echo ""
else
	make -C asm clean
endif
	
