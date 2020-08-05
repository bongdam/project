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
ifneq ($(CONFIG_RTL_8197F_VG),)
BTCODE_DIR=btcode_vg
else
BTCODE_DIR=btcode
endif



TOOLCFLAGS	=
TOOLLDFLAGS	= -n

OPT	=  -G 0

TEXT	=

INCLUDES	= -I../bsp -I. -I./include

CFLAGS	= -march=mips32r2 -g -Wall -fomit-frame-pointer -fno-pic $(TOOLCFLAGS) $(OPT) $(INCLUDES)\
          -D__KERNEL__\
          -Dlinux\
          -O

#CFLAGS += -mno-abicalls
#CFLAGS += -save-temps
CFLAGS += -gdwarf-2
CFLAGS += -fno-builtin
#CFLAGS += -Werror
ifeq ($(CONFIG_DECREASE_BOOTSIZE),y)
CFLAGS +=  -fdata-sections -ffunction-sections -Os
endif
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

ifeq ($(CONFIG_8211F_SUPPORT),y)
CFLAGS += -I./rtl_nfbi/
endif

ifeq ($(CONFIG_NAND_FLASH_BOOTING),y)
LDFLAGS = -nostdlib  -T./ld.script_nand  -EL   --static
else
ifeq ($(CONFIG_DECREASE_BOOTSIZE),y)
LDFLAGS = -nostdlib  -T./ld_decrease_bootsize.script  -EL   --static
else
LDFLAGS = -nostdlib  -T./ld.script  -EL   --static
endif
endif
WLDFLAGS = -nostdlib  -T./ldw.script  -EL   --static

ifeq ($(CONFIG_DECREASE_BOOTSIZE),y)
LDFLAGS += --gc-sections
WLDFLAGS += --gc-sections
endif

ASFLAGS	=  -D__ASSEMBLY__  -x assembler-with-cpp -G 0


CRT	=
LIBS	=

.SUFFIXES : .s .S .c .o .out .nm .img .sr .sre .text .bin .scr

all:
	@echo "No rules to make target. You should choose:"
	@echo "make { boot | wboot }  boot for general, wboot for wrapped boot code"

.PHONY: banner
banner:	cr-output
	@echo  \#define BOOT_CODE_TIME \"`date "+%Y.%m.%d-%H:%M%z"`\" > ./banner/mk_time

cr-output:
	@if [ ! -d Output ]; then \
	mkdir Output; \
	fi

#wboot(wrapped) means boot code will be wrapped in this code
wboot: build_asm banner $(OUTDIR)/wboot.out
	$(NM)	./Output/wboot.out | sort > ./Output/wboot.nm
	$(OBJCOPY) -g -Obinary ./Output/wboot.out ./Output/wboot.img
	$(OBJDUMP) -h -S ./Output/wboot.out > ./Output/wboot.text


#all :	"$(OUTDIR)" boot.out
boot: build_asm banner $(OUTDIR)/boot.out
	$(NM)	./Output/boot.out | sort > ./Output/boot.nm
	$(OBJCOPY) -Obinary ./Output/boot.out ./Output/boot.img
	#$(OBJCOPY)  -g -Obinary ./Output/boot.out ./Output/boot.img
	$(OBJDUMP) -h -S ./Output/boot.out > ./Output/boot.text
#david
	cp ./Output/boot.img ../$(BTCODE_DIR)/boot.img -f

#"$(OUTDIR)" :

#---- build_asm ----------------------------------
MAKE_ASM = ./make.asm
build_asm:
ifeq (,$(wildcard $(MAKE_ASM)))
	echo ""
else
	make -f $(MAKE_ASM)
endif

clean_asm:
ifeq (,$(wildcard $(MAKE_ASM)))
	echo ""
else
	make -f $(MAKE_ASM) clean
endif
#--------------------------------------

##Assembly file######################################################
##########################head.o must be the first.
ASMLIST =
ASMLIST += ./arch/mips/kernel/head.S
ASMLIST += ./init/inthandler.S
ASMLIST += ./arch/mips/kernel/cache.S

###Assembly OBJ file, auto create ###################################

ASMOBJS = $(addprefix $(OUTDIR)/,$(addsuffix .o,$(notdir $(basename $(ASMLIST))) ))

$(ASMOBJS):$(ASMLIST)
	$(CC) -c $(CFLAGS) $(ASFLAGS) $(filter %$(addsuffix .S,$(notdir $(basename $@))),$(ASMLIST) ) -o $@

##C file#############################################################
SRCLIST =
SRCLIST += ./init/irq.c
SRCLIST += ./init/eth_tftpd.c

ifdef CONFIG_NEW_CONSOLE_SUPPORT
SRCLIST += ./io/shelltask.c
endif

#-----------------------------------------------------------------------------

#ifdef CONFIG_RTL_819X_SWCORE
SRCLIST += ./init/ethInt_865x.c
SRCLIST += ./rtl8196x/swCore.c
SRCLIST += ./rtl8196x/swNic_poll.c
SRCLIST += ./rtl8196x/swTable.c
SRCLIST += ./rtl8196x/vlanTable.c
#endif

ifdef CONFIG_8211F_SUPPORT
SRCLIST += ./rtl_nfbi/rtl_nfbi.c
endif

#----------------------------------------------------------------------------
ifdef CONFIG_SPI_FLASH
SRCLIST += ./flash/spi-sheipa.c
SRCLIST += ./flash/m25p80.c
SRCLIST += ./flash/spi.c
endif

ifdef CONFIG_NOR_FLASH
SRCLIST += ./flash/flash.c
endif

ifdef CONFIG_NAND_FLASH_BOOTING
CFLAGS += -DCONFIG_NAND_FLASH_BOOTING
endif

ifdef CONFIG_NAND_FLASH
CFLAGS += -DCONFIG_NAND_FLASH
CFLAGS += -D__RTK_BOOT__
SRCLIST += ./nand_flash/rtk_nand.c
SRCLIST += ./nand_flash/rtkn_nand/ops_rtknand.c

ifdef CONFIG_SPI_NAND_FLASH
SRCLIST += ./nand_flash/rtkn_nand/nand_spi_ctrl.c
SRCLIST += ./nand_flash/rtkn_nand/nand_spi_ecc_ctrl.c
SRCLIST += ./nand_flash/rtkn_nand/nand_spi.c
SRCLIST += ./nand_flash/rtk_nand_spi.c
SRCLIST += ./nand_flash/rtkn_nand/rtkn_spi_nand_chip_param.c
CFLAGS += -DCONFIG_SPI_NAND_FLASH
ifdef CONFIG_NAND_SPI_USE_DIO
CFLAGS += -DCONFIG_NAND_SPI_USE_DIO
endif
ifdef CONFIG_NAND_SPI_USE_QIO
CFLAGS += -DNAND_SPI_USE_QIO -DCONFIG_NAND_SPI_USE_QIO
endif
ifdef CONFIG_NAND_SPI_USE_DATA_IOx2
CFLAGS += -DCONFIG_NAND_SPI_USE_DATA_IOx2
endif
ifdef CONFIG_NAND_SPI_USE_DATA_IOx4
CFLAGS += -DCONFIG_NAND_SPI_USE_DATA_IOx4
endif
ifdef CONFIG_NAND_SPI_PROGRAM_USE_DATA_IOx4
CFLAGS += -DCONFIG_NAND_SPI_PROGRAM_USE_DATA_IOx4
endif
endif

ifdef CONFIG_PARALLEL_NAND_FLASH
SRCLIST += ./nand_flash/rtkn_nand/nand_parallel_ctrl.c
SRCLIST += ./nand_flash/rtk_nand_parallel.c
CFLAGS += -DCONFIG_PARALLEL_NAND_FLASH
endif

ifdef CONFIG_RTK_REMAP_BBT
SRCLIST += ./nand_flash/rtkn_nand/rtknflash_bbtOps.c
SRCLIST += ./nand_flash/rtkn_nand/rtknflash_bbt.c
CFLAGS += -DCONFIG_RTK_REMAP_BBT
endif

ifdef CONFIG_RTK_NORMAL_BBT
SRCLIST += ./nand_flash/rtkn_nand/rtknflash_bbtOps.c
SRCLIST += ./nand_flash/rtkn_nand/rtknflash_bbt.c
CFLAGS += -DCONFIG_RTK_NORMAL_BBT
endif

endif

ifdef CONFIG_CRYPTO_DEV_REALTEK
SRCLIST += ./crypto/rtl_crypto.c
#SRCLIST += ./crypto/rtl_crypto_helper.c
SRCLIST += ./crypto/crypto_engine/rtl_ipsec.c
SRCLIST += ./crypto/crypto_engine/sha1.c
SRCLIST += ./crypto/crypto_engine/md5.c
SRCLIST += ./crypto/crypto_engine/hmac.c
SRCLIST += ./crypto/crypto_engine/sw_sim/aes_core.c

SRCLIST += ./crypto/rtl_crypto_wrapper.c
CFLAGS += -I./crypto -I./crypto/crypto_engine/  -D__RTK_BOOT__ -DCONFIG_CPU_LITTLE_ENDIAN -DCONFIG_RTL_8197F -D_LITTLE_ENDIAN -DCONFIG_CRYPTO_DEV_REALTEK
ifdef CONFIG_CRYPTO_DEV_REALTEK_TEST

#SRCLIST += ./crypto/crypto_engine/rtk_crypto_test.c
#SRCLIST += ./crypto/crypto_engine/cryptoSim_aes.c
SRCLIST += ./crypto/crypto_engine/rtl_ipsec_test.c
SRCLIST += ./crypto/crypto_engine/sw_sim/authSim.c
SRCLIST += ./crypto/crypto_engine/sw_sim/des_setkey.c
SRCLIST += ./crypto/crypto_engine/sw_sim/des_ecb.c
SRCLIST += ./crypto/crypto_engine/sw_sim/desSim.c
#SRCLIST += ./crypto/crypto_engine/sw_sim/aes_core.c
SRCLIST += ./crypto/crypto_engine/sw_sim/aes_block.c
SRCLIST += ./crypto/crypto_engine/sw_sim/aesSim.c

CFLAGS += -DCONFIG_CRYPTO_DEV_REALTEK_TEST
endif
endif

#jffs2
ifdef CONFIG_FS_JFFS2
SRCLIST += ./fs/jffs2/cmd_jffs2.c
SRCLIST += ./fs/jffs2/compr_rtime.c
SRCLIST += ./fs/jffs2/compr_rubin.c
SRCLIST += ./fs/jffs2/compr_zlib.c
SRCLIST += ./fs/jffs2/jffs2_1pass.c
SRCLIST += ./fs/jffs2/mini_inflate.c
SRCLIST += ./fs/jffs2/jffs2_wrapper.c
ifdef CONFIG_JFFS2_LZO
SRCLIST += ./fs/jffs2/compr_lzo.c
endif
CFLAGS += -DCONFIG_FS_JFFS2 -D__RTK_BOOT__
CFLAGS += -DJFFS2_PART_OFFSET=$(CONFIG_JFFS2_PART_OFFSET) -DJFFS2_PART_SIZE=$(CONFIG_JFFS2_PART_SIZE)

ifdef CONFIG_NAND_FLASH
CFLAGS += -DCONFIG_JFFS2_NAND -DCONFIG_CMD_NAND
endif
ifdef CONFIG_SPI_FLASH
CFLAGS += -DCONFIG_CMD_FLASH
endif
endif
#--------------------------------------
ifdef CONFIG_I2C_POLLING
SRCLIST += ./i2c/extend/dw_hal_i2c.c
SRCLIST += ./i2c/base/dw_i2c_base.c
SRCLIST += ./i2c/base/dw_i2c.c
SRCLIST += ./i2c/base/i2c.c
endif
#--------------------------------------
ifeq ($(CONFIG_DHCP_SERVER),y)
SRCLIST += ./init/dhcpd.c
endif
#--------------------------------------
ifeq ($(CONFIG_IIS_TEST),y)
SRCLIST += ./monitor/i2s/iis_isr.c
#SRCLIST += ./monitor/i2s/ALC5621.c
#SRCLIST += ./monitor/i2s/fpga_gpio.c
CFLAGS += -DCONFIG_IIS_TEST #-save-temps
endif
#--------------------------------------
ifeq ($(CONFIG_RLX5181_TEST),y)
SRCLIST += ./monitor/5181.S
endif


SRCLIST += ./arch/mips/kernel/setup.c
SRCLIST += ./arch/mips/kernel/cache_c.c

SRCLIST += ./init/main.c
SRCLIST += ./init/calloc.c


SRCLIST += ./io/init.c
SRCLIST += ./io/string.c
SRCLIST += ./io/strtol.c
SRCLIST += ./io/strtoul.c
SRCLIST += ./io/ctool.c
SRCLIST += ./io/misc.c

#SRCLIST += ./monitor/test_8168n.c
SRCLIST += ./monitor/test_hw_97f.c
#SRCLIST += ./monitor/test_hw_96e.c
ifndef CONFIG_RTL8196E
SRCLIST += ./monitor/xmodem.c
endif

SRCLIST += ./init/utility.c

ifeq ($(CONFIG_RTL_FAST_CHECKSUM_ENABLE),y)
SRCLIST += ./init/fastcksum.c
endif

ifeq ($(CONFIG_PARAM_PASSING),y)
SRCLIST += ./init/bootm.c
endif

ifeq ($(CONFIG_HTTP_SERVER),y)
SRCLIST += ./init/utcp.c
endif

ifeq ($(CONFIG_SW_8367R),y)
SRCLIST += ./rtl8367r/rtk_api.c
SRCLIST += ./rtl8367r/rtl8367b_asicdrv.c
SRCLIST += ./rtl8367r/rtl8367b_asicdrv_cputag.c
SRCLIST += ./rtl8367r/rtl8367b_asicdrv_phy.c
SRCLIST += ./rtl8367r/rtl8367b_asicdrv_port.c
SRCLIST += ./rtl8367r/smi.c
SRCLIST += ./rtl8367r/gpio.c
endif

ifeq ($(CONFIG_SD_CARD_BOOTING),y)
SRCLIST += ./fs/diskio.c
SRCLIST += ./fs/ff.c
SRCLIST += ./sdcard/sdcard.c
CFLAGS += -I../$(BTCODE_DIR)/
endif

ifeq ($(CONFIG_SW_83XX),y)
SRCLIST += ./rtl83xx/rtk_api.c
SRCLIST += ./rtl83xx/rtl8367c_asicdrv.c
SRCLIST += ./rtl83xx/rtl8367c_asicdrv_cputag.c
SRCLIST += ./rtl83xx/rtl8367c_asicdrv_phy.c
SRCLIST += ./rtl83xx/rtl8367c_asicdrv_port.c
SRCLIST += ./rtl83xx/smi.c
SRCLIST += ./rtl83xx/gpio.c
SRCLIST += ./rtl83xx/rtk_switch.c
SRCLIST += ./rtl83xx/led.c
SRCLIST += ./rtl83xx/port.c
SRCLIST += ./rtl83xx/cpu.c
SRCLIST += ./rtl83xx/rate.c
SRCLIST += ./rtl83xx/rtl8367c_asicdrv_led.c
SRCLIST += ./rtl83xx/rtl8367c_asicdrv_green.c
SRCLIST += ./rtl83xx/rtl8367c_asicdrv_misc.c
SRCLIST += ./rtl83xx/rtl8367c_asicdrv_lut.c
SRCLIST += ./rtl83xx/rtl8367c_asicdrv_rma.c
SRCLIST += ./rtl83xx/rtl8367c_asicdrv_mirror.c
SRCLIST += ./rtl83xx/rtl8367c_asicdrv_portIsolation.c
SRCLIST += ./rtl83xx/rtl8367c_asicdrv_meter.c
SRCLIST += ./rtl83xx/rtl8367c_asicdrv_scheduling.c
SRCLIST += ./rtl83xx/rtl8367c_asicdrv_inbwctrl.c
endif
CFLAGS += -D__DAVO__
SRCLIST += ./init/nvram.c
CFLAGS_nvram := -I$(ROOTDIR)/../staging_dir/include -D__PRELOADER__

# Generate signature files
.PHONY: ed25519 FORCE
ed25519: FORCE
	@echo "====> compile verify_signature"
	@echo \#define LINUX_PUB_KEY \"$(shell sed -n '1p' keys/linux_pub_key.txt)\" >signature.h
	@echo \#define ROOTFS_PUB_KEY \"$(shell sed -n '1p' keys/rootfs_pub_key.txt)\" >>signature.h
	cp -a signature.h ed25519-donna/
	$(CC) -c -DED25519_TEST -DED25519_REFHASH -o verify_signature -c ed25519-donna/ed25519.c

###C OBJ file, auto create ###############################################
OBJS	= $(addprefix $(OUTDIR)/,$(addsuffix .o,$(notdir $(basename $(SRCLIST))) ))
OBJS   += ./init/rtl_wrapper.o

sig_check :=
ifeq ($(CONFIG_RTK_LINUX_SECURE),y)
sig_check += ./verify_signature
else
ifeq ($(CONFIG_RTK_ROOTFS_SECURE),y)
sig_check += ./verify_signature
endif
endif

define PROGRAM_template
$(addprefix $(OUTDIR)/,$(addsuffix .o,$(notdir $(basename $(1))))) : $(1)
#	@echo $(1)
#	@echo $(addprefix $(OUTDIR)/,$(addsuffix .o,$(notdir $(basename $(1))) ))
	$(CC) -c $(CFLAGS) $$(CFLAGS_$$(notdir $$*)) $(1) -o $$@
endef

$(foreach fname,$(SRCLIST),$(eval $(call PROGRAM_template,$(fname))))

#-----------------------------------------------------------------------------
$(OUTDIR)/monitor.o: ./monitor/monitor.c
	$(CC) -c $(CFLAGS) -o $(OUTDIR)/monitor.o ./monitor/monitor.c

$(OUTDIR)/wmonitor.o: ./monitor/monitor.c
	$(CC) -c $(CFLAGSW) -o $(OUTDIR)/wmonitor.o ./monitor/monitor.c



$(OUTDIR)/boot.out :	  $(ASMOBJS) $(OBJS) $(OUTDIR)/monitor.o ed25519
	$(LD) $(LDFLAGS)  $(ASMOBJS) $(OBJS) $(OUTDIR)/monitor.o  $(LIBS) $(sig_check) -o $(OUTDIR)/boot.out

$(OUTDIR)/temp.o: temp.c
	$(CC) -c $(CFLAGS) -o $(OUTDIR)/temp.o temp.c
	$(OBJCOPY) --add-section .btimg=$(OUTDIR)/boot $(OUTDIR)/temp.o

$(OUTDIR)/wboot.out :	   $(ASMOBJS) $(OBJS) $(OUTDIR)/temp.o $(OUTDIR)/wmonitor.o ed25519
	$(LD) $(WLDFLAGS)  $(ASMOBJS) $(OBJS) $(OUTDIR)/temp.o $(OUTDIR)/wmonitor.o $(LIBS) $(sig_check) -o $(OUTDIR)/wboot.out

#------------------------------------------------------------------------------------------------------
clean : clean_asm
	$(RM) -f $(OBJS)
	$(RM) -f $(OUTDIR)/boot.out $(OUTDIR)/boot.text $(OUTDIR)/boot.nm $(OUTDIR)/boot.img $(OUTDIR)/boot.bin
	$(RM) -f $(OUTDIR)/boot.cdb $(OUTDIR)/monitor.o $(OUTDIR)/wmonitor.o $(OUTDIR)/wboot.*
	$(RM) -f $(OUTDIR)/temp.o $(OUTDIR)/boot
	@find $(OUTDIR) -type f -name '*.o' -exec rm -f {} \;


