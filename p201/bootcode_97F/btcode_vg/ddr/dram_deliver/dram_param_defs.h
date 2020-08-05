#ifndef __MS_DRAM_PARA_H
#define __MS_DRAM_PARA_H

#define  SDR_IDR                  0x03100000
#define  DDR2_IDR                 0x0310dd20
#define  DDR3_IDR                 0x0310dd30
#define  DDR2_IDR_EXTRA           0x0310dd20
#define  DDR3_IDR_EXTRA           0x0310dd30


#define  WRAP_CR_MISC_DQ32        0x64         //    # page_size=4k, paralle, bst8, bank8 
#define  WRAP_CR_MISC_DQ16        0x63         //    # page_size=2k,         bst8, bank8 

 
#define  PCTL_CR_DDR2_DCR_DQ32    0x212        //      #DFI=2:1, DDR2, dq32
#ifdef RTK_PHY
#define  PCTL_CR_DDR2_DCR_DQ16    0x232        //      #DFI=2:1, DDR2
#define  PCTL_CR_DDR2_IOCR        0x101000     //      #tphy_wrdata= 0x1, CAS=6, CWL=5
#define  PCTL_CR_DDR2_MR          0x1263       //      #Normal pwr_down, WR=2, CAS=6, BST =8
#else // XILINX_PHY
#define  PCTL_CR_DDR2_DCR_DQ16    0x202        //      #DFI=2:1, DDR2
#define  PCTL_CR_DDR2_IOCR        0x1000       //      #tphy_wrdata= 0x1
#define  PCTL_CR_DDR2_MR          0x1233       //      #Normal pwr_down, WR=2, CAS=3, BST =8
#endif // RTK_PHY
//#define  PCTL_CR_DDR2_MR          0x1232     //          #Normal pwr_down, WR=2, CAS=3, BST =4
#define  PCTL_CR_DDR2_EMR1        0x6       
#define  PCTL_CR_DDR2_EMR2        0x00         //      #CWL_Latency
#define  PCTL_CR_DDR2_DRR         0x080a0006   //      #tref=0x8af0(isu 8 times), trfc=0x6 
#define  PCTL_CR_DDR2_TPR0        0x2431       //      #trtp=1, twr=2, tras=3, trp=1 
#define  PCTL_CR_DDR2_TPR1        0x528431     //      #trtw=5, twtr=1, tccd=2, trcd=1, trc=0x3, trrd=0x1 
#define  PCTL_CR_DDR2_TPR2        0x5424       //      #tmrd=2 

#define  PCTL_CR_DDR3_DCR_DQ32    0x213        // #DFI=2:1, DDR3, dq16
#ifdef RTK_PHY
#define  PCTL_CR_DDR3_DCR_DQ16    0x233        // #DFI=2:1, DDR3
#define  PCTL_CR_DDR3_IOCR        0x101000     //      #tphy_wrdata= 0x1, CAS=6, CWL=5
#define  PCTL_CR_DDR3_MR          0x0220       //      #Normal pwr_down, WR=2, CAS=6, BST =8
#else // XILINX_PHY
#define  PCTL_CR_DDR3_DCR_DQ16    0x203        // #DFI=2:1, DDR3
#define  PCTL_CR_DDR3_IOCR        0x1000       //      #tphy_wrdata= 0x1
#define  PCTL_CR_DDR3_MR          0x0210       //      #Normal pwr_down, WR=2, CAS=5, BST =8
#endif // RTK_PHY
//#define  PCTL_CR_DDR3_MR         0x1232      //      #Normal pwr_down, WR=2, CAS=3, BST =4
#define  PCTL_CR_DDR3_EMR1        0x6      
#define  PCTL_CR_DDR3_EMR2        0x00         //      #CWL_Latency =5
#define  PCTL_CR_DDR3_DRR         0x080a7006   //      #tref=0x0af0(isu 8 times), trfc=0x6 

#define  PCTL_CR_DDR3_TPR0        0x4431       //      #trtp=2, twr=2, tras=3, trp=1 
#define  PCTL_CR_DDR3_TPR1        0x528432     //      #trtw=5, twtr=1, tccd=2, trcd=1, trc=0x3, trrd=0x2 
#define  PCTL_CR_DDR3_TPR2        0x7424       //      #tmrd=3 

#define  PCTL_CR_CSR              0x700 

#ifndef LANGUAGE_ASSEMBLY

#include "dram_device_info.h"
#include "dram_param_custom.h"

#if 1
struct dram_info pll_dram_dev = {
  DDR_3,  
  PAGE_1K, 
  BANK_8,
  // DQ_32
  HALF_DQ32
};
#else
//for SDR 32 MB
struct dram_info pll_dram_dev = {
  SDR,  
  PAGE_1K, 
  BANK_4,
   DQ_16
  //HALF_DQ32
};

#endif

#if 0
struct dram_mode_reg_info pll_dram_mode_reg_1866 = {
  BST_LEN_8, 
  SENQUENTIAL,
  0x3, // mode0_cas: 13 
  0x7, // mode0_wr:14 
  1,   // mode1_dll_en_n  
  0,   // mode1_all_lat=0
  4    // mode2_cwl:9
};

struct dram_timing_info pll_dram_timing_1866 = {
  110000,     // trfc_ps;
  70312500,   // trefi_ps;
  16,         // wr_max_tck;
  13090,      // trcd_ps; 
  13090,      // trp_ps;
  33000,      // tras_ps;
  4,          // trrd_tck;
  15000,      // twr_ps;
  4,          // twtr_tck; 
  //13090,      // trp_ps;
  4,          // tmrd_tck;
  4,          // trtp_tck;
  4,          // tccd_tck;
  48090       // trc_ps;
};

struct dram_mode_reg_info pll_dram_mode_reg_1190 = {
  BST_LEN_8, 
  SENQUENTIAL,
  0x4, // mode0_cas: 6  
  0x1, // mode0_wr:5  
  1,   // mode1_dll_en_n  
  0,   // mode1_all_lat=0
  0    // mode2_cwl:5
};

struct dram_timing_info pll_dram_timing_1190 = {
  110000,     // trfc_ps;
  70312500,   // trefi_ps;
  16,         // wr_max_tck;
  13125,      // trcd_ps; 
  13125,      // trp_ps;
  37500,      // tras_ps;
  4,          // trrd_tck;
  15000,      // twr_ps;
  4,          // twtr_tck; 
  //13090,      // trp_ps;
  4,          // tmrd_tck;
  4,          // trtp_tck;
  4,          // tccd_tck;
  50625       // trc_ps;
};

struct dram_info sdr_dram_dev = {
  SDR,  
  PAGE_1K, 
  BANK_4, 
  DQ_16
};

#if 0
struct dram_mode_reg_info sdr_dram_mode_reg = {
  BST_LEN_8, 
  SENQUENTIAL,
  0x3, // mode0_cas: 3 
  0x0, // mode0_wr 
  1,   // mode1_dll_en_n  
  0,   // mode1_all_lat  
  0    // mode2_cwl   
};
#else
//SDR
struct dram_mode_reg_info sdr_dram_mode_reg = {
  BST_LEN_8, 
  //BST_LEN_8, 
  SENQUENTIAL,
  0x3, // mode0_cas: 3 
  0x0, // mode0_wr 
  1,   // mode1_dll_en_n  
  0,   // mode1_all_lat  
  0    // mode2_cwl   
};
#endif

struct dram_info ddr1_dram_dev = {
  DDR_1,  
  PAGE_1K, 
  BANK_4, 
  HALF_DQ32
};

struct dram_mode_reg_info ddr1_dram_mode_reg = {
  BST_LEN_8, 
  SENQUENTIAL,
  0x3, // mode0_cas: 3 
  0x0, // mode0_wr 
  1,   // mode1_dll_en_n  
  0,   // mode1_all_lat  
  0    // mode2_cwl   
};


struct dram_timing_info sdr_dram_timing = {
  66000,      // trfc_ps;
  63999800,   // trefi_ps;
  2,          // wr_max_tck;
  15000,      // trcd_ps; 
  15000,      // trp_ps;
  37000,      // tras_ps;
  2,          // trrd_tck;
  7000,       // twr_ps;
  0,          // twtr_tck; 
  //13090,      // trp_ps;
  2,          // tmrd_tck;
  0,          // trtp_tck;
  1,          // tccd_tck;
  60000       // trc_ps;
};

struct dram_timing_info ddr1_dram_timing = {
  66000,      // trfc_ps;
  69999800,   // trefi_ps;
  2,          // wr_max_tck;
  15000,      // trcd_ps; 
  15000,      // trp_ps;
  40000,      // tras_ps;
  2,          // trrd_tck;
  1500,       // twr_ps;
  2,          // twtr_tck; 
  //13090,      // trp_ps;
  2,          // tmrd_tck;
  0,          // trtp_tck;
  1,          // tccd_tck;
  55000       // trc_ps;
};

struct dram_device_info pll_dram_info_1866 = {
  &pll_dram_dev,
  &pll_dram_mode_reg_1866,
  &pll_dram_timing_1866,
  //1126          // ddr_period_ps
  1080,         // ddr_period_ps
  DFI_RATIO_2
};

struct dram_device_info dll_dram_info_1866 = {
  &pll_dram_dev,
  &pll_dram_mode_reg_1866,
  &pll_dram_timing_1866,
  //1094          // ddr_period_ps
  1080,         // ddr_period_ps
  DFI_RATIO_2
};

struct dram_device_info pll_dram_info = {
  &pll_dram_dev,
  &pll_dram_mode_reg_1190,
  &pll_dram_timing_1190,
  //1126          // ddr_period_ps
  //1080,         // ddr_period_ps
  1700,         // ddr_period_ps: DDR:1190
  DFI_RATIO_2
};

struct dram_device_info dll_dram_info = {
  &pll_dram_dev,
  &pll_dram_mode_reg_1190,
  &pll_dram_timing_1190,
  //1094          // ddr_period_ps
  //1080,         // ddr_period_ps
  1700,         // ddr_period_ps: DDR:1190
  DFI_RATIO_2
};


struct dram_device_info sdr_dram_info = {
  &sdr_dram_dev,
  &sdr_dram_mode_reg,
  &sdr_dram_timing,
  //1094          // ddr_period_ps
  7500,           // ddr_period_ps
  DFI_RATIO_1
};

struct dram_device_info ddr1_dram_info = {
  &ddr1_dram_dev,
  &ddr1_dram_mode_reg,
  &ddr1_dram_timing,
  20000,          // ddr_period_ps, DDR= 200
  DFI_RATIO_1
};
#endif
#define PHY_ADDR_CMD_LATENCY 7
#define PHY_WRITE_DATA_LATENCY 6
#define PHY_DQS_LATENCY 8               //maybe should read phy ip register 0x244
#define PHY_READ_LATENCY 1             // PHY_DQS_LATENCY - PHY_ADDR_CMD_LATENCY

#if 0
const struct dram_info ddr3_dev = {
  DDR_3,  
  PAGE_4K, 
  BANK_4, 
  HALF_DQ32
}; // ddr3_dev

const struct dram_mode_reg_info ddr3_mode_reg_25mhz = {
  BST_LEN_8, 
  SENQUENTIAL,
  0x4, // mode0_cas: 6
  0x6, // mode0_wr:12  ,it seems useless
  0,   // mode1_dll_en_n  ,enable
  0,   // mode1_all_lat=0 ,it seems useless
  0,   // mode2_cwl:5  
  0,   // dram_par_lat, parity_lat
  4,   // dram_wr_lat, cr_mrinfo_wr_lat
  6,  // dram_rd_lat, cr_mrinfo_rd_lat , This is mostly the same as CAS latency
  0    // dram_add_lat, cr_mrinfo_add_lat
}; // ddr3_mode_reg_1600mhz

const struct dram_timing_info ddr3_timing_25mhz = {
  160000,     // trfc_ps;
  60000000,   // trefi_ps;
  12,         // wr_max_tck;  //TODO: need to fix to 62.5Mhz
  14000,      // trcd_ps; 
  14000,      // trp_ps;
  35000,      // tras_ps;
  4,          // trrd_tck;
  15000,      // twr_ps;
  4,          // twtr_tck;    // TODO, seems set to zero is fine
  //13090,      // trp_ps;
  //4,          // tmrd_tck;
  4,           // tmrd_tck
  4,          // trtp_tck;
  4,          // tccd_tck;   // it should be 4 , but the code has add 1 to this field, so I try to set 3
  50000,      // trc_ps;
  0,          // tccd_s_tck;
  0           // twtr_s_tck;
}; // ddr3_timing_1600mhz

const struct dram_device_info ddr3_dram_info_FPGA = {
  &ddr3_dev,
  &ddr3_mode_reg_25mhz,
  &ddr3_timing_25mhz,
  16000,          // ddr_period_ps, DDR= 62.5MHz 
  DFI_RATIO_1
};

//=========================================
const struct dram_timing_info sdr_dram_timing = {
  66000,      // trfc_ps;
  63999800,   // trefi_ps;
  2,          // wr_max_tck;
  15000,      // trcd_ps; 
  15000,      // trp_ps;
  37000,      // tras_ps;
  2,          // trrd_tck;
  7000,       // twr_ps;
  0,          // twtr_tck; 
  //13090,      // trp_ps;
  2,          // tmrd_tck;
  0,          // trtp_tck;
  1,          // tccd_tck;
  60000       // trc_ps;
};


const struct dram_mode_reg_info sdr_dram_mode_reg = {
  BST_LEN_8, 
  //BST_LEN_8, 
  SENQUENTIAL,
  0x3, // mode0_cas: 3 
  0x0, // mode0_wr 
  1,   // mode1_dll_en_n  
  0,   // mode1_all_lat  
  0    // mode2_cwl   
};

const struct dram_info sdr_dram_dev = {
  SDR,  
  PAGE_1K, 
  BANK_4, 
  DQ_16
};


const struct dram_device_info sdr_dram_info = {
  &sdr_dram_dev,
  &sdr_dram_mode_reg,
  &sdr_dram_timing,
  //1094          // ddr_period_ps
  7500,           // ddr_period_ps
  DFI_RATIO_1
};
#endif
//===================DRAM_INFO=========================
const struct dram_info ddr1_dev = {
  DDR_1,  
  PAGE_1K, 
  BANK_4, 
  HALF_DQ32
}; // ddr1_dev

const struct dram_info ddr2_dram_M14D5121632A_dev = {
  DDR_2,  
  PAGE_2K, 
  BANK_4, 
  HALF_DQ32
};

//=================DRAM MODE REGISTER=====================

const struct dram_mode_reg_info ddr2_800_dram_M14D5121632A_mode_reg = {
  BST_LEN_4, 
  SENQUENTIAL,
  0x7, // mode0_cas: 7
  0x0, // mode0_wr 
  0,   // mode1_dll_en_n  
  0,   // mode1_ocd;      //1 -> 70%, 0 -> 100% Brian: 100%
  0x10, // mode1_odt;    //0x1 -> 75,   0x10 -> 150,  0x11 -> 50
  0,   // mode1_all_lat  
  0,    // mode2_cwl   
  0,   // parity_lat
  6,   // cr_mrinfo_wr_lat
  7,   // cr_mrinfo_rd_lat
  0    // cr_mrinfo_add_lat  
};

#if 1//def CONFIG_AUTO_PARAM_DDR_SWITCH
// joyce new
const struct dram_mode_reg_info ddr2_800_dram_M14D5121632A_mode_reg_C = {
  BST_LEN_4,
  SENQUENTIAL,
  0x7, // mode0_cas: 7
  0x0, // mode0_wr
  0,   // mode1_dll_en_n
  0,   // mode1_ocd;      //1 -> 70%, 0 -> 100%
  0x10, // mode1_odt;    //0x1 -> 75,   0x10 -> 150,  0x11 -> 50
  0,   // mode1_all_lat
  0,    // mode2_cwl
  0,   // parity_lat
  6,   // cr_mrinfo_wr_lat
  7,   // cr_mrinfo_rd_lat
  0    // cr_mrinfo_add_lat
};
#endif

const struct dram_mode_reg_info ddr2_1066_dram_M14D5121632A_mode_reg = {
  BST_LEN_4, 
  SENQUENTIAL,
  0x7, // mode0_cas: 7
  0x0, // mode0_wr 
  0,   // mode1_dll_en_n  
  0,   // mode1_ocd;      //1 -> 70%, 0 -> 100%
  0x10, // mode1_odt;    //0x1 -> 75,   0x10 -> 150,  0x11 -> 50
  0,   // mode1_all_lat  
  0,    // mode2_cwl   
  0,   // parity_lat
  6,   // cr_mrinfo_wr_lat
  7,   // cr_mrinfo_rd_lat
  0    // cr_mrinfo_add_lat  
};

#if 0
const struct dram_mode_reg_info ddr2_400_dram_8197FB_mode_reg = {
  BST_LEN_8, 
  SENQUENTIAL,
  0x7, // mode0_cas: 7
  0x0, // mode0_wr 
  1,   // mode1_dll_en_n  
  0,   // mode1_all_lat  
  0,    // mode2_cwl   
  0,   // parity_lat
  6,   // cr_mrinfo_wr_lat
  7,   // cr_mrinfo_rd_lat
  0    // cr_mrinfo_add_lat  
};
#endif

const struct dram_mode_reg_info ddr1_mode_reg_400mhz = {
  BST_LEN_8, 
  SENQUENTIAL,
  0x3, // mode0_cas: 3 
  0x0, // mode0_wr 
  0,   // mode1_dll_en_n  
  1,   // mode1_ocd;	  //1 -> 70%, 0 -> 100%
  0x1, // mode1_odt;	//0x1 -> 75,   0x10 -> 150,  0x11 -> 50
  0,   // mode1_all_lat=0
  0,   // mode2_cwl:5
  0,   // parity_lat
  1,   // cr_mrinfo_wr_lat
  3,   // cr_mrinfo_rd_lat
  0    // cr_mrinfo_add_lat  
}; // ddr1_mode_reg_400mhz
#if 1
const struct dram_mode_reg_info ddr1_mode_reg_500mhz = {
  BST_LEN_8, 
  SENQUENTIAL,
  0x3, // mode0_cas: 3 
  0x0, // mode0_wr 
  0,   // mode1_dll_en_n 
  1,   // mode1_ocd;	  //1 -> 70%, 0 -> 100%
  0x1, // mode1_odt;	//0x1 -> 75,   0x10 -> 150,  0x11 -> 50
  0,   // mode1_all_lat=0
  0,   // mode2_cwl:5
  0,   // parity_lat
  1,   // cr_mrinfo_wr_lat
  3,   // cr_mrinfo_rd_lat
  0    // cr_mrinfo_add_lat  
}; // ddr1_mode_reg_500mhz
#endif

//================DRAM Timing info=======================
const struct dram_timing_info ddr1_timing_400mhz = {
  DRAM_512M_TRFC,      // trfc_ps; 70000
  69999800,   // trefi_ps;
  3,          // wr_max_tck;
  15000,      // trcd_ps; 
  15000,      // trp_ps;
  40000,      // tras_ps;
  2,          // trrd_tck;
  15000,       // twr_ps;
  2,          // twtr_tck; 
  //13090,      // trp_ps;
  2,          // tmrd_tck;
  0,          // trtp_tck;
  1,          // tccd_tck;
  55000,      // trc_ps;
  0,		  // tccd_s_tck;
  0, 		  // twtr_s_tck;
  3,    //  tcke_tck;
  0,    // tzqcs_tck;
  50000       // tfaw_ps;
}; // ddr1_timing_400mhz
#if 1
const struct dram_timing_info ddr1_timing_500mhz = {
  DRAM_512M_TRFC,      // trfc_ps; 70000
  69999800,   // trefi_ps;
  3,          // wr_max_tck;
  15000,      // trcd_ps; 
  15000,      // trp_ps;
  40000,      // tras_ps;
  2,          // trrd_tck;
  15000,       // twr_ps;
  2,          // twtr_tck; 
  //13090,      // trp_ps;
  2,          // tmrd_tck;
  0,          // trtp_tck;
  1,          // tccd_tck;
  55000,      // trc_ps;
  0,		  // tccd_s_tck;
  0, 		  // twtr_s_tck;
  3,    //  tcke_tck;
  0,    // tzqcs_tck;
  50000       // tfaw_ps;
}; // ddr1_timing_400mhz
#endif
const uint32_t ddr2_trft_with_size[]=
{
	(uint32_t)8,		(uint32_t)16,	(uint32_t)32,	(uint32_t)64, 	 	(uint32_t)128, 	 (uint32_t)256,		(uint32_t)512,		(uint32_t)0, //Size
	(uint32_t)75000, 	(uint32_t)75000,(uint32_t)75000,(uint32_t)105000, 	(uint32_t)127500,(uint32_t)197500,	(uint32_t)327500,	(uint32_t)0, //E
	(uint32_t)75000, 	(uint32_t)75000,(uint32_t)75000,(uint32_t)105000, 	(uint32_t)127500,(uint32_t)197500,	(uint32_t)327500, 	(uint32_t)0  //W
};

const uint32_t ddr2_tfaw_with_page_size[]=
{
	(uint32_t)1,		(uint32_t)2,	(uint32_t)0,
	(uint32_t)35000, 	(uint32_t)45000,(uint32_t)0
};

const uint32_t ddr2_cmd_driving[]=
{   
	(uint32_t)32,	(uint32_t)64, (uint32_t)128, (uint32_t)0x0, //Size
  	(uint32_t)0xf,  (uint32_t)0x0, (uint32_t)0xf, (uint32_t)0x0 //cmd_driving
};


const struct dram_timing_info ddr2_800_dram_M14D5121632A_timing = {
  DRAM_512M_TRFC,      // trfc_ps;
  17000000,   // trefi_ps;     //todo 69999800
  8,          // wr_max_tck;    // todo
  15000,      // trcd_ps; 
  15000,      // trp_ps;
  45000,      // tras_ps;
  4,          // trrd_tck;          //todo
  15000,       // twr_ps;
  3,          // twtr_tck;          //todo
  //13090,      // trp_ps;
  2,          // tmrd_tck;
  3,          // trtp_tck;          //todo
  2,          // tccd_tck;
  57500,       // trc_ps;
  0,		  // tccd_s_tck;
  0, 		  // twtr_s_tck;
  3,    //  tcke_tck;
  0,    // tzqcs_tck;
  50000       // tfaw_ps;
};


const struct dram_timing_info ddr2_1066_dram_M14D5121632A_timing = {
  DRAM_512M_TRFC,      // trfc_ps;
  17000000,   // trefi_ps;     //todo
  8,          // wr_max_tck;    // todo
  13125,      // trcd_ps; 
  13250,      // trp_ps;
  45000,      // tras_ps;
  6,          // trrd_tck;          //todo
  15000,       // twr_ps;
  4,          // twtr_tck;          //todo
  //13090,      // trp_ps;
  2,          // tmrd_tck;
  4,          // trtp_tck;          //todo
  2,          // tccd_tck;
  58125,       // trc_ps;
  0,		  // tccd_s_tck;
  0, 		  // twtr_s_tck;
  3,    //  tcke_tck;
  0,    // tzqcs_tck;
  50000       // tfaw_ps;
};

//==================PHY PARAMETER INFO==================
const struct dram_phy_ip_info ddr2_phy_mcm_800 = {
  1,  // mck_default; winbond 6; etron 3
  0, // mdqs_default;  winbond 7; etron -15
  0xe,	//  dqs_en_default;
  0xa,	//  rx_fifo_default; 
  0x3fc, // odt_default;
  0xff0,	// dqs_driving;   //nnt, npt, pnt,ppt, 0x25c
  0xff, // dck_driving;   //nnt, npt, pnt,ppt, 0x264
  0xf, // cmd_driving;   //nt,pt, 0x210
  0x0,	// ba_addr_driving;   //nt,pt, 0x214
  0xf0,	//uint8_t dq_driving;   //nt,pt, 0x218
  0x12111211,  // rx_delay_tap_0;  //bit 0 ~ 3, default 0x10101010, 0x28c
  0x12111111,  // rx_delay_tap_1;  //bit 4 ~ 7, default 0x10101010 , 0x29c
  0x11121111,  // rx_delay_tap_3;  //bit 8 ~ 11, default 0x10101010, 0x290
  0x12111111,  // rx_delay_tap_4;  //bit 12 ~ 15, default 0x10101010 , 0x2a0
  0x12121312,  // rx_delay_tap_0; //bit 0 ~ 3, default 0x10101010, 0x2ac
  0x12121212,  // rx_delay_tap_1; //bit 4 ~ 7, default 0x10101010 , 0x2bc
  0x11121112,  // rx_delay_tap_3; //bit 8 ~ 11, default 0x10101010, 0x2b0
  0x12121211,  // rx_delay_tap_4; //bit 12 ~ 15, default 0x10101010 , 0x2c0
  0x33333333,  //bit 0 ~ 7, default 0x33333333, 0x26c
  0x33333333,  //bit 8 ~ 15, default 0x33333333, 0x270
  0x33333333,  //bit 0 ~ 7, default 0x33333333, 0x27c
  0x33333333,  //bit 8 ~ 15, default 0x33333333, 0x280
  0x66666666,  // tx_delay_tap_0;  // bit 0 ~ 7, default 0x44444444
  0x66666666,  // tx_delay_tap_1; // bit 8 ~ 15, default 0x44444444
  0x5444,  //dqs_dm_delay_tap; bit 15~0 dm: bit 7~4 bit 12~15 , default 0x4444  loca:0x240
 0x44444444, // bit 0 ~ 7, default 0x44444444, 0x200
  0x44444444, // bit 8 ~ 15, default 0x44444444, 0x204
  0x444, // bank adr 0 ~ 2, default 0x0444, 0x208
  0x444444, // CKE[3:0], RAS[7:4], CAS[11:8], WE[15:12], CS[19:16], ODT[23:20], default 0x00444444, 0x20c
  0x80200DF, // only for bitfile => BIT_DCK_POWER_SEL[28:20], BIT_DCK_LDO_VSEL[19:18], BIT_DCK_DLY_SEL[8:4]
  0x11117777 // CAL_SHIFT_CTRL
};

#if 1
//==================PHY PARAMETER INFO==================
const struct dram_phy_ip_info ddr2_phy_mcm_1066 = {
  1,  // mck_default; winbond 6; etron 3
  0, // mdqs_default;  winbond 7; etron -15
  0xe, //  dqs_en_default; 
  0xa, //  rx_fifo_default; 
  0x3fc, // odt_default;
  0xff0, // dqs_driving;   //nnt, npt, pnt,ppt, 0x25c
  0xff, // dck_driving;   //nnt, npt, pnt,ppt, 0x264
  0xf, // cmd_driving;   //nt,pt, 0x210
  0x0, // ba_addr_driving;   //nt,pt, 0x214
  0xf0, //uint8_t dq_driving;   //nt,pt, 0x218
  0x12111211,  // rx_delay_tap_0;  //bit 0 ~ 3, default 0x10101010, 0x28c
  0x12111111,  // rx_delay_tap_1;  //bit 4 ~ 7, default 0x10101010 , 0x29c
  0x11121111,  // rx_delay_tap_3;  //bit 8 ~ 11, default 0x10101010, 0x290
  0x12111111,  // rx_delay_tap_4;  //bit 12 ~ 15, default 0x10101010 , 0x2a0
  0x12121312,  // rx_delay_tap_0; //bit 0 ~ 3, default 0x10101010, 0x2ac
  0x12121212,  // rx_delay_tap_1; //bit 4 ~ 7, default 0x10101010 , 0x2bc
  0x11121112,  // rx_delay_tap_3; //bit 8 ~ 11, default 0x10101010, 0x2b0
  0x12121211,  // rx_delay_tap_4; //bit 12 ~ 15, default 0x10101010 , 0x2c0
  0x33333333,  //bit 0 ~ 7, default 0x33333333, 0x26c
  0x33333333,  //bit 8 ~ 15, default 0x33333333, 0x270
  0x33333333,  //bit 0 ~ 7, default 0x33333333, 0x27c
  0x33333333,  //bit 8 ~ 15, default 0x33333333, 0x280
  0x66666666,  // tx_delay_tap_0;  // bit 0 ~ 7, default 0x44444444
  0x66666666,  // tx_delay_tap_1; // bit 8 ~ 15, default 0x44444444
  0x5444,  //dqs_dm_delay_tap; bit 15~0 dm: bit 7~4 bit 12~15 , default 0x4444  loca:0x240
  0x44444444, // bit 0 ~ 7, default 0x44444444, 0x200
  0x44444444, // bit 8 ~ 15, default 0x44444444, 0x204
  0x444, // bank adr 0 ~ 2, default 0x0444, 0x208
  0x444444, // CKE[3:0], RAS[7:4], CAS[11:8], WE[15:12], CS[19:16], ODT[23:20], default  0x00444444, 0x20c
  0x80200DF, // only for bitfile => BIT_DCK_POWER_SEL[28:20], BIT_DCK_LDO_VSEL[19:18], BIT_DCK_DLY_SEL[8:4]
  0x11117777 // CAL_SHIFT_CTRL
};
#endif
#ifdef CONFIG_AUTO_PARAM_DDR_SWITCH
//==================PHY PARAMETER INFO==================
const struct dram_phy_ip_info ddr2_phy_mcm_1066_B = {
  6,		// mck_default; winbond 6; etron 3
  7,	// mdqs_default;  winbond 7; etron -15
  0xe,	//  dqs_en_default; 
  0xa,	//  rx_fifo_default; 
  0x7f8,	// odt_default;
  0xff0,	// dqs_driving;   //nnt, npt, pnt,ppt, 0x25c
  0xff,	// dck_driving;   //nnt, npt, pnt,ppt, 0x264
  0x0,	// cmd_driving;   //nt,pt, 0x210
  0x0,	// ba_addr_driving;   //nt,pt, 0x214
  0xf0,	//uint8_t dq_driving;   //nt,pt, 0x218
  0x0e0e0e0e, 	// rx_delay_tap_0;  //bit 0 ~ 3, default 0x10101010, 0x28c
  0x0e0e0e0e,		// rx_delay_tap_1;  //bit 4 ~ 7, default 0x10101010 , 0x29c
  0x0e0e0e0e,		// rx_delay_tap_3;  //bit 8 ~ 11, default 0x10101010, 0x290
  0x0e0e0e0e,		// rx_delay_tap_4;  //bit 12 ~ 15, default 0x10101010 , 0x2a0
  0x0e0e0e0e,		// rx_delay_tap_0;	//bit 0 ~ 3, default 0x10101010, 0x2ac
  0x0e0e0e0e,		// rx_delay_tap_1;	//bit 4 ~ 7, default 0x10101010 , 0x2bc
  0x0e0e0e0e,		// rx_delay_tap_3;	//bit 8 ~ 11, default 0x10101010, 0x2b0
  0x0e0e0e0e,		// rx_delay_tap_4;	//bit 12 ~ 15, default 0x10101010 , 0x2c0
  0x55555555, 	//bit 0 ~ 7, default 0x33333333, 0x26c
  0x55555555, 	//bit 8 ~ 15, default 0x33333333, 0x270
  0x55555555,		//bit 0 ~ 7, default 0x33333333, 0x27c
  0x55555555,		//bit 8 ~ 15, default 0x33333333, 0x280
  0x66666666,		// tx_delay_tap_0;  // bit 0 ~ 7, default 0x44444444
  0x66666666,		// tx_delay_tap_1;	// bit 8 ~ 15, default 0x44444444
  0x6464,		//dqs_dm_delay_tap; bit 15~0 dm: bit 7~4 bit 12~15 , default 0x4444  loca:0x240
 0x44444444, // bit 0 ~ 7, default 0x44444444, 0x200
  0x44444444, // bit 8 ~ 15, default 0x44444444, 0x204
  0x444, // bank adr 0 ~ 2, default 0x0444, 0x208
  0x444444, // CKE[3:0], RAS[7:4], CAS[11:8], WE[15:12], CS[19:16], ODT[23:20], default 0x00444444, 0x20c
};

//==================PHY PARAMETER INFO==================
const struct dram_phy_ip_info ddr2_phy_mcm_1066_C = {
  1,  // mck_default; winbond 6; etron 3
  0, // mdqs_default;  winbond 7; etron -15
  0xe,	//  dqs_en_default; 
  0xa,	//  rx_fifo_default; 
  0x3fc, // odt_default;
  0xff0,	// dqs_driving;   //nnt, npt, pnt,ppt, 0x25c
  0xff,	// dck_driving;   //nnt, npt, pnt,ppt, 0x264
  0x0, // cmd_driving;   //nt,pt, 0x210
  0x0,	// ba_addr_driving;   //nt,pt, 0x214
  0xf0, //uint8_t dq_driving;   //nt,pt, 0x218
  0x12111211,  // rx_delay_tap_0;  //bit 0 ~ 3, default 0x10101010, 0x28c
  0x12111111,  // rx_delay_tap_1;  //bit 4 ~ 7, default 0x10101010 , 0x29c
  0x11121111,  // rx_delay_tap_3;  //bit 8 ~ 11, default 0x10101010, 0x290
  0x12111111,  // rx_delay_tap_4;  //bit 12 ~ 15, default 0x10101010 , 0x2a0
  0x12121312,  // rx_delay_tap_0; //bit 0 ~ 3, default 0x10101010, 0x2ac
  0x12121212,  // rx_delay_tap_1; //bit 4 ~ 7, default 0x10101010 , 0x2bc
  0x11121112,  // rx_delay_tap_3; //bit 8 ~ 11, default 0x10101010, 0x2b0
  0x12121211,  // rx_delay_tap_4; //bit 12 ~ 15, default 0x10101010 , 0x2c0
  0x33333333,  //bit 0 ~ 7, default 0x33333333, 0x26c
  0x33333333,  //bit 8 ~ 15, default 0x33333333, 0x270
  0x33333333,  //bit 0 ~ 7, default 0x33333333, 0x27c
  0x33333333,  //bit 8 ~ 15, default 0x33333333, 0x280
  0x66666666,		// tx_delay_tap_0;  // bit 0 ~ 7, default 0x44444444
  0x66666666,		// tx_delay_tap_1;	// bit 8 ~ 15, default 0x44444444
  0x5444,  //dqs_dm_delay_tap; bit 15~0 dm: bit 7~4 bit 12~15 , default 0x4444  loca:0x240
   0x44444444, // bit 0 ~ 7, default 0x44444444, 0x200
  0x44444444, // bit 8 ~ 15, default 0x44444444, 0x204
  0x444, // bank adr 0 ~ 2, default 0x0444, 0x208
  0x444444, // CKE[3:0], RAS[7:4], CAS[11:8], WE[15:12], CS[19:16], ODT[23:20], default 0x00444444, 0x20c
  0x80200DF, // only for bitfile => BIT_DCK_POWER_SEL[28:20], BIT_DCK_LDO_VSEL[19:18], BIT_DCK_DLY_SEL[8:4]
  0x11117777 // CAL_SHIFT_CTRL
};
#endif
/*
const struct dram_phy_ip_info ddr2_phy_mcm_1066_C_test = {
  .mck_default = 5,
	.mdqs_default = -7,
	.dqs_en_default = 0x0000000e,
	.rx_fifo_default = 0x0000000a,
	.odt_default = 0x000007fc,
	.dqs_driving = 0x000000ff, //default value
	.dck_driving = 0x000000ff, //default value
	.cmd_driving = 0x00000000, //default value
	.ba_addr_driving = 0x00000000, //default value
	.dq_driving = 0x0000000f, //default value
	.rx_delay_tap_0 = 0x0f0f0f0f,
	.rx_delay_tap_1 = 0x0f0f0f0f,
	.rx_delay_tap_2 = 0x0f0f0f0f,
	.rx_delay_tap_3 = 0x0f0f0f0f,
	.rx_delay_tap_n_0 = 0x0f0f0f0f,
	.rx_delay_tap_n_1 = 0x0f0f0f0f,
	.rx_delay_tap_n_2 = 0x0f0f0f0f,
	.rx_delay_tap_n_3 = 0x0f0f0f0f,
	.pre_shift_0 = 0x44444444,
	.pre_shift_1 = 0x44444444,
	.post_shift_0 = 0x44444444,
	.post_shift_1 = 0x44444444,
	.tx_delay_tap_0 = 0x44444444,
	.tx_delay_tap_1 = 0x44444444,
	.dqs_dm_delay_tap = 0x4444,
};*/

const struct dram_phy_ip_info ddr1_phy_mcm_400 = {
  0,           // mck_default; 
  0,           // mdqs_default; 
  0xc,       //  dqs_en_default;
  0x9,       //  rx_fifo_default;
  0x3ff,     // odt_default;
  0x55,     // dqs_driving;   //nnt, npt, pnt,ppt, 0x25c
  0x00,     // dck_driving;   //nnt, npt, pnt,ppt, 0x264
  0x0,       // cmd_driving;   //nt,pt, 0x210
  0x0,       // ba_addr_driving;   //nt,pt, 0x214
  0x5,       //uint8_t dq_driving;   //nt,pt, 0x218
  0x10101010,         // rx_delay_tap_0;  //bit 0 ~ 3, default 0x10101010, 0x28c
  0x10101010,         // rx_delay_tap_1;  //bit 4 ~ 7, default 0x10101010 , 0x29c
  0x10101010,         // rx_delay_tap_3;  //bit 8 ~ 11, default 0x10101010, 0x290
  0x10101010,         // rx_delay_tap_4;  //bit 12 ~ 15, default 0x10101010 , 0x2a0
  0x15131413,         // rx_delay_tap_0;  //bit 0 ~ 3, default 0x10101010, 0x2ac
  0x11151314,         // rx_delay_tap_1;  //bit 4 ~ 7, default 0x10101010 , 0x2bc
  0x15141617,         // rx_delay_tap_3;  //bit 8 ~ 11, default 0x10101010, 0x2b0
  0x17141616,         // rx_delay_tap_4;  //bit 12 ~ 15, default 0x10101010 , 0x2c0
  0x33333333,         //bit 0 ~ 7, default 0x33333333, 0x26c
  0x33333333,         //bit 8 ~ 15, default 0x33333333, 0x270
  0x33333333,         //bit 0 ~ 7, default 0x33333333, 0x27c
  0x33333333,         //bit 8 ~ 15, default 0x33333333, 0x280
  0x44444444,         // tx_delay_tap_0;  // bit 0 ~ 7, default 0x44444444
  0x44444444,         // tx_delay_tap_1;  // bit 8 ~ 15, default 0x44444444
  0x4444,		// dqs_dm_delay_tap; bit 15~0 dm: bit 7~4 bit 12~15 , default 0x4444  loca:0x240
  0x44444444, // address bit 0 ~ 7, default 0x44444444, 0x200, Tina: 0x18280438
  0x44444444, //address bit 8 ~ 15, default 0x44444444, 0x204, Tina: 0x44444448
  0x444, // bank adr 0 ~ 2, default 0x0444, 0x208, Tina: 0x000
  0x444444, // CKE[3:0], RAS[7:4], CAS[11:8], WE[15:12], CS[19:16], ODT[23:20], default 0x00444444, 0x20c, Tina:0xff577f 
  0x80200DF, // only for bitfile => BIT_DCK_POWER_SEL[28:20], BIT_DCK_LDO_VSEL[19:18], BIT_DCK_DLY_SEL[8:4]
  0x11117777 // CAL_SHIFT_CTRL
};
#if 1
const struct dram_phy_ip_info ddr1_phy_mcm_500 = {
  0,           // mck_default; 
  0,           // mdqs_default; 
  0xc,       //  dqs_en_default;
  0x9,       //  rx_fifo_default;
  0x3ff,     // odt_default;
  0x55,     // dqs_driving;   //nnt, npt, pnt,ppt, 0x25c
  0x00,     // dck_driving;   //nnt, npt, pnt,ppt, 0x264
  0x0,       // cmd_driving;   //nt,pt, 0x210
  0x0,       // ba_addr_driving;   //nt,pt, 0x214
  0x5,       //uint8_t dq_driving;   //nt,pt, 0x218
  0x10101010,         // rx_delay_tap_0;  //bit 0 ~ 3, default 0x10101010, 0x28c
  0x10101010,         // rx_delay_tap_1;  //bit 4 ~ 7, default 0x10101010 , 0x29c
  0x10101010,         // rx_delay_tap_3;  //bit 8 ~ 11, default 0x10101010, 0x290
  0x10101010,         // rx_delay_tap_4;  //bit 12 ~ 15, default 0x10101010 , 0x2a0
  0x15131413,         // rx_delay_tap_0;  //bit 0 ~ 3, default 0x10101010, 0x2ac
  0x11151314,         // rx_delay_tap_1;  //bit 4 ~ 7, default 0x10101010 , 0x2bc
  0x15141617,         // rx_delay_tap_3;  //bit 8 ~ 11, default 0x10101010, 0x2b0
  0x17141616,         // rx_delay_tap_4;  //bit 12 ~ 15, default 0x10101010 , 0x2c0
  0x33333333,         //bit 0 ~ 7, default 0x33333333, 0x26c
  0x33333333,         //bit 8 ~ 15, default 0x33333333, 0x270
  0x33333333,         //bit 0 ~ 7, default 0x33333333, 0x27c
  0x33333333,         //bit 8 ~ 15, default 0x33333333, 0x280
  0x44444444,         // tx_delay_tap_0;  // bit 0 ~ 7, default 0x44444444
  0x44444444,         // tx_delay_tap_1;  // bit 8 ~ 15, default 0x44444444
  0x4444,		// dqs_dm_delay_tap; bit 15~0 dm: bit 7~4 bit 12~15 , default 0x4444  loca:0x240
  0x44444444, // address bit 0 ~ 7, default 0x44444444, 0x200, Tina: 0x18280438
  0x44444444, //address bit 8 ~ 15, default 0x44444444, 0x204, Tina: 0x44444448
  0x444, // bank adr 0 ~ 2, default 0x0444, 0x208, Tina: 0x000
  0x444444, // CKE[3:0], RAS[7:4], CAS[11:8], WE[15:12], CS[19:16], ODT[23:20], default 0x00444444, 0x20c, Tina:0xff577f 
  0x80200DF, // only for bitfile => BIT_DCK_POWER_SEL[28:20], BIT_DCK_LDO_VSEL[19:18], BIT_DCK_DLY_SEL[8:4]
  0x11117777 // CAL_SHIFT_CTRL
};
#endif
//==================DRAM INFO=========================

const struct dram_device_info ddr1_400_dram_info = { // reference Winbond W9425G6JH 4m * 4 banks * 16 bits
  &ddr1_dev,
  &ddr1_mode_reg_400mhz,
  &ddr1_timing_400mhz,
  &ddr1_phy_mcm_400,
  5000,          // ddr_period_ps, DDR= 400
  (enum     dfi_ratio_type     *)DFI_RATIO_1
};

#if 1
const struct dram_device_info ddr1_500_dram_info = {  // reference Winbond W9425G6JH 4m * 4 banks * 16 bits
  &ddr1_dev,
  &ddr1_mode_reg_500mhz,
  &ddr1_timing_500mhz,
  &ddr1_phy_mcm_500,
  4000,          // ddr_period_ps, DDR= 500
  (enum     dfi_ratio_type     *) DFI_RATIO_1
};
#endif

const struct dram_device_info ddr2_800_dram_M14D5121632A_info = {
  &ddr2_dram_M14D5121632A_dev,
  &ddr2_800_dram_M14D5121632A_mode_reg,
  &ddr2_800_dram_M14D5121632A_timing,
  &ddr2_phy_mcm_1066,
  2500,          // ddr_period_ps, DDR2= 800
  (enum     dfi_ratio_type     *)DFI_RATIO_1
};
#if 1
const struct dram_device_info ddr2_1066_dram_M14D5121632A_info = {
  &ddr2_dram_M14D5121632A_dev,
  &ddr2_1066_dram_M14D5121632A_mode_reg,
  &ddr2_1066_dram_M14D5121632A_timing,
  &ddr2_phy_mcm_1066,
  1876,          // ddr_period_ps, DDR2= 1066  1876
  (enum     dfi_ratio_type     *)DFI_RATIO_1
};
#endif
#ifdef CONFIG_AUTO_PARAM_DDR_SWITCH
const struct dram_device_info ddr2_1066_dram_M14D5121632A_info_B = {
  &ddr2_dram_M14D5121632A_dev,
  &ddr2_1066_dram_M14D5121632A_mode_reg,
  &ddr2_1066_dram_M14D5121632A_timing,
  &ddr2_phy_mcm_1066_B,
  1876,          // ddr_period_ps, DDR2= 1066  1876
  (enum     dfi_ratio_type     *)DFI_RATIO_1
};

const struct dram_device_info ddr2_1066_dram_M14D5121632A_info_C = {
  &ddr2_dram_M14D5121632A_dev,
  &ddr2_1066_dram_M14D5121632A_mode_reg,
  &ddr2_1066_dram_M14D5121632A_timing,
  &ddr2_phy_mcm_1066_C,
  1876,          // ddr_period_ps, DDR2= 1066  1876
  (enum     dfi_ratio_type     *)DFI_RATIO_1
};

//joyce new
/*
const struct dram_device_info ddr2_1066_dram_M14D5121632A_info_C_128MB = {
  &ddr2_dram_M14D5121632A_dev,
  &ddr2_1066_dram_M14D5121632A_mode_reg,
  &ddr2_1066_dram_M14D5121632A_timing_128MB,
  &ddr2_phy_mcm_1066_C,
  1876,          // ddr_period_ps, DDR2= 1066  1876
  (enum     dfi_ratio_type     *)DFI_RATIO_1
};
*/

const struct dram_device_info ddr2_800_dram_M14D5121632A_info_C = {
  &ddr2_dram_M14D5121632A_dev,
  &ddr2_800_dram_M14D5121632A_mode_reg_C,
  &ddr2_800_dram_M14D5121632A_timing,
  &ddr2_phy_mcm_1066_C,
  2500,          // ddr_period_ps, DDR2= 1066  1876
  (enum     dfi_ratio_type     *)DFI_RATIO_1
};

//joyce new
/*
const struct dram_device_info ddr2_800_dram_M14D5121632A_info_C_128MB = {
  &ddr2_dram_M14D5121632A_dev,
  &ddr2_800_dram_M14D5121632A_mode_reg_C,
  &ddr2_800_dram_M14D5121632A_timing_128MB,
  &ddr2_phy_mcm_1066_C,
  2500,          // ddr_period_ps, DDR2= 1066  1876
  (enum     dfi_ratio_type     *)DFI_RATIO_1
};*/
#endif

#ifdef CONFIG_SDRAM_400_temp
const struct dram_phy_ip_info ddr2_phy_temp_400 = {
  0,		// mck_default; 
  0,		// mdqs_default; 
  0xe,	//  dqs_en_default;
  0x9,	//  rx_fifo_default;
  0x1f0,	// odt_default;
  0xff0,	// dqs_driving;   //nnt, npt, pnt,ppt, 0x25c
  0x00,	// dck_driving;   //nnt, npt, pnt,ppt, 0x264
  0x0,	// cmd_driving;   //nt,pt, 0x210
  0x0,	// ba_addr_driving;   //nt,pt, 0x214
  0x50,	//uint8_t dq_driving;   //nt,pt, 0x218
  0x10101010, 	// rx_delay_tap_0;  //bit 0 ~ 3, default 0x10101010, 0x28c
  0x10101010,		// rx_delay_tap_1;  //bit 4 ~ 7, default 0x10101010 , 0x29c
  0x10101010,		// rx_delay_tap_3;  //bit 8 ~ 11, default 0x10101010, 0x290
  0x10101010,		// rx_delay_tap_4;  //bit 12 ~ 15, default 0x10101010 , 0x2a0
  0x10101010,		// rx_delay_tap_0;	//bit 0 ~ 3, default 0x10101010, 0x2ac
  0x10101010,		// rx_delay_tap_1;	//bit 4 ~ 7, default 0x10101010 , 0x2bc
  0x10101010,		// rx_delay_tap_3;	//bit 8 ~ 11, default 0x10101010, 0x2b0
  0x10101010,		// rx_delay_tap_4;	//bit 12 ~ 15, default 0x10101010 , 0x2c0
  0x33333333, 	//bit 0 ~ 7, default 0x33333333, 0x26c
  0x33333333, 	//bit 8 ~ 15, default 0x33333333, 0x270
  0x33333333,		//bit 0 ~ 7, default 0x33333333, 0x27c
  0x33333333,		//bit 8 ~ 15, default 0x33333333, 0x280
  0x44444444,		// tx_delay_tap_0;  // bit 0 ~ 7, default 0x44444444
  0x44444444,		// tx_delay_tap_1;	// bit 8 ~ 15, default 0x44444444
  0x4444,		// dqs_dm_delay_tap; bit 15~0 dm: bit 7~4 bit 12~15 , default 0x4444  loca:0x240
  0x44444444, // address bit 0 ~ 7, default 0x44444444, 0x200, Tina: 0x18280438
  0x44444444, //address bit 8 ~ 15, default 0x44444444, 0x204, Tina: 0x44444448
  0x444, // bank adr 0 ~ 2, default 0x0444, 0x208, Tina: 0x000
  0x444444, // CKE[3:0], RAS[7:4], CAS[11:8], WE[15:12], CS[19:16], ODT[23:20], default 0x00444444, 0x20c, Tina:0xff577f 
};

const struct dram_mode_reg_info ddr2_400_dram_M14D5121632A_mode_reg = {
  BST_LEN_8, 
  SENQUENTIAL,
  0x7, // mode0_cas: 7
  0x0, // mode0_wr 
  0,   // mode1_dll_en_n  
  0,   // mode1_all_lat  
  0,    // mode2_cwl   
  0,   // parity_lat
  6,   // cr_mrinfo_wr_lat
  7,   // cr_mrinfo_rd_lat
  0    // cr_mrinfo_add_lat  
};

//400 phy 
const struct dram_device_info ddr2_400_dram_M14D5121632A_info = {
  &ddr2_dram_M14D5121632A_dev,
  &ddr2_400_dram_M14D5121632A_mode_reg,
  &ddr2_1066_dram_M14D5121632A_timing,
  &ddr2_phy_temp_400,
  5000,          // ddr_period_ps, DDR2= 400, 200MHz CLK
  (enum     dfi_ratio_type     *)DFI_RATIO_1
};
#endif

/******************************************************
****
**** The below is for discret DDR2 memory
**** 
*******************************************************/
#ifdef CONFIG_AUTO_DISCRET_DDR_SWITCH
const struct dram_mode_reg_info ddr2_800_dram_discret_mode_reg = {
   BST_LEN_8,
   SENQUENTIAL,
   0x5, // mode0_cas: 5
   0x0, // mode0_wr
   0,   // mode1_dll_en_n
   0,   // mode1_ocd;      //1 -> 70%, 0 -> 100%
   0x10, // mode1_odt;    //0x1 -> 75,   0x10 -> 150,  0x11 -> 50
   0,   // mode1_all_lat
   0,    // mode2_cwl
   0,   // parity_lat
   6,   // cr_mrinfo_wr_lat
   7,   // cr_mrinfo_rd_lat
   0    // cr_mrinfo_add_lat
 };

const struct dram_mode_reg_info ddr2_1066_dram_discret_mode_reg = {
  BST_LEN_8, 
  SENQUENTIAL,
  0x7, // mode0_cas: 5
  0x0, // mode0_wr 
  0,   // mode1_dll_en_n  
  0,   // mode1_ocd;      //1 -> 70%, 0 -> 100%
  0x10, // mode1_odt;    //0x1 -> 75,   0x10 -> 150,  0x11 -> 50
  0,   // mode1_all_lat  
  0,    // mode2_cwl   
  0,   // parity_lat
  4,   // cr_mrinfo_wr_lat, wl=rl-1
  5,   // cr_mrinfo_rd_lat, rl=al+cl
  0    // cr_mrinfo_add_lat  
};

#ifdef DDR_SINGLE_DISCRETE
#if 0
const struct dram_phy_ip_info ddr2_phy_discret_800 = {
  11,         // mck_default;  //Stevie set: 12 //8 //11
  35,         // mdqs_default; //Stevie set: 14 //-16 //30 35
  0xf,        //  dqs_en_default; //Stevie set:0xf
  0xb,       //  rx_fifo_default; // Stevie set:oxb
  0x1f0,    // odt_default; 0x1f0
  0xff0,      // dqs_driving;   //nnt, npt, pnt,ppt, 0x25c
  0xff,     // dck_driving;   //nnt, npt, pnt,ppt, 0x264
  0x0,       // cmd_driving;   //nt,pt, 0x210  //Stevie set:0xa
  0x0,       // ba_addr_driving;   //nt,pt, 0x214  //Stevie set:0xa
  0x50,       //uint8_t dq_driving;   //nt,pt, 0x218
  0x09090909,         // rx_delay_tap_0;  //bit 0 ~ 3, rising, default 0x10101010, 0x28c //Stevie set 0x15111611
  0x09090909,         // rx_delay_tap_1;  //bit 4 ~ 7, rising, default 0x10101010 , 0x29c //Stevie set 0x12141216
  0x09090909,         // rx_delay_tap_3;  //bit 8 ~ 11, rising, default 0x10101010, 0x290 //Stevie set 0x13121413
  0x09090909,         // rx_delay_tap_4;  //bit 12 ~ 15, rising, default 0x10101010 , 0x2a0 //Stevie set 0x13131213
  0x09090909,         // rx_delay_tap_0;  //bit 0 ~ 3, falling, default 0x10101010, 0x2ac //Stevie set 0x14111511
  0x09090909,         // rx_delay_tap_1;  //bit 4 ~ 7, falling, default 0x10101010 , 0x2bc //Stevie set 0x11141115
  0x09090909,         // rx_delay_tap_3;  //bit 8 ~ 11, falling, default 0x10101010, 0x2b0 //Stevie set 0x12111312
  0x09090909,         // rx_delay_tap_4;  //bit 12 ~ 15, falling, default 0x10101010 , 0x2c0 //Stevie set 0x13131312
  0x11111111,         //bit 0 ~ 7, default 0x33333333, 0x26c, original0x33333333
  0x11111111,         //bit 8 ~ 15, default 0x33333333, 0x270, original0x33333333
  0x11111111,         //bit 0 ~ 7, default 0x33333333, 0x27c, original0x33333333
  0x11111111,         //bit 8 ~ 15, default 0x33333333, 0x280, original0x33333333
  0x44444444,         // tx_delay_tap_0;  // bit 0 ~ 7, default 0x44444444     //mask also needs to be modified in dram_init_dpi_ip_ASIC.
  0x44444444,         // tx_delay_tap_1;   // bit 8 ~ 15, default 0x44444444  //mask also needs to be modified in dram_init_dpi_ip_ASIC.
  0x4444,		// dqs_dm_delay_tap; bit 15~0 dm: bit 7~4 bit 12~15 , default 0x4444  loca:0x240
 0x44444444, // address bit 0 ~ 7, default 0x44444444, 0x200, Tina: 0x18280438
  0x44444444, //address bit 8 ~ 15, default 0x44444444, 0x204, Tina: 0x44444448
  0x444, // bank adr 0 ~ 2, default 0x0444, 0x208, Tina: 0x000
  0x444444, // CKE[3:0], RAS[7:4], CAS[11:8], WE[15:12], CS[19:16], ODT[23:20], default 0x00444444, 0x20c, Tina:0xff577f 
};
#else


#if 1




const struct dram_phy_ip_info ddr2_phy_discret_800 = {
  10,         // mck_default;  //Stevie set: 12 //8 //11
  14,         // mdqs_default; //Stevie set: 14 //-16 //30 35
  0xe,        //  dqs_en_default; //Stevie set:0xf
  0xa,       //  rx_fifo_default; // Stevie set:oxb
  0x1f0,    // odt_default; 0x1f0
  0xffa,      // dqs_driving;   //se[0], sden[1], pd[2], e2[3], ppt[5:4], pnt[7:6], npt[9:8], nnt[11:10], 0x25c  //sden=1, e2=1
  0xff,     // dck_driving;   //nnt, npt, pnt,ppt, 0x264
  0xf,       // cmd_driving;   //nt,pt, 0x210  //Stevie set:0xa
  0x3,       // ba_addr_driving;   //nt,pt, 0x214  //Stevie set:0xa
  0x50,       //uint8_t dq_driving;   //smt[0],sden[1],pd[2], e2[3], nt[5:4],pt[7:6], 0x218
  0x11111111,         // rx_delay_tap_0;  //bit 0 ~ 3, rising, default 0x10101010, 0x28c //Stevie set 0x15111611
  0x11111111,         // rx_delay_tap_1;  //bit 4 ~ 7, rising, default 0x10101010 , 0x29c //Stevie set 0x12141216
  0x11111111,         // rx_delay_tap_3;  //bit 8 ~ 11, rising, default 0x10101010, 0x290 //Stevie set 0x13121413
  0x11111111,         // rx_delay_tap_4;  //bit 12 ~ 15, rising, default 0x10101010 , 0x2a0 //Stevie set 0x13131213
  0x11111111,         // rx_delay_tap_0;  //bit 0 ~ 3, falling, default 0x10101010, 0x2ac //Stevie set 0x14111511
  0x11111111,         // rx_delay_tap_1;  //bit 4 ~ 7, falling, default 0x10101010 , 0x2bc //Stevie set 0x11141115
  0x11111111,         // rx_delay_tap_3;  //bit 8 ~ 11, falling, default 0x10101010, 0x2b0 //Stevie set 0x12111312
  0x11111111,         // rx_delay_tap_4;  //bit 12 ~ 15, falling, default 0x10101010 , 0x2c0 //Stevie set 0x13131312
  0x44444444,         //bit 0 ~ 7, default 0x33333333, 0x26c, original0x33333333
  0x44444444,         //bit 8 ~ 15, default 0x33333333, 0x270, original0x33333333
  0x44444444,         //bit 0 ~ 7, default 0x33333333, 0x27c, original0x33333333
  0x44444444,         //bit 8 ~ 15, default 0x33333333, 0x280, original0x33333333
  0x44444444,          // tx_delay_tap_0;  // bit 0 ~ 7, default 0x44444444     //mask also needs to be modified in dram_init_dpi_ip_ASIC.
  0x44444444,          // tx_delay_tap_1;   // bit 8 ~ 15, default 0x44444444  //mask also needs to be modified in dram_init_dpi_ip_ASIC.
  0x4444,         // dqs_dm_delay_tap; bit 15~0 dm: bit 7~4 bit 12~15 , default 0x4444  loca:0x240
 0x44444444, // address bit 0 ~ 7, default 0x44444444, 0x200, Tina: 0x18280438
  0x44444444, //address bit 8 ~ 15, default 0x44444444, 0x204, Tina: 0x44444448
  0x444, // bank adr 0 ~ 2, default 0x0444, 0x208, Tina: 0x000
  0x444444, // CKE[3:0], RAS[7:4], CAS[11:8], WE[15:12], CS[19:16], ODT[23:20], default 0x00444444, 0x20c, Tina:0xff577f 
};

#endif

#endif
#endif

#ifdef DDR_TWO_DISCRETE_WINBOND
const struct dram_phy_ip_info ddr2_phy_discret_800 = {
  8,         // mck_default;  //Stevie set: 12 //8 //11
  26,         // mdqs_default; //Stevie set: 14 //-16 //30 35
  0xf,        //  dqs_en_default; //Stevie set:0xf
  0xb,       //  rx_fifo_default; // Stevie set:oxb
  0x1f0,    // odt_default; 0x1f0
  0xffa,      // dqs_driving;   //se[0], sden[1], pd[2], e2[3], ppt[5:4], pnt[7:6], npt[9:8], nnt[11:10], 0x25c  //sden=1, e2=1
  0xff,     // dck_driving;   //nnt, npt, pnt,ppt, 0x264
  0xf,       // cmd_driving;   //nt,pt, 0x210  //Stevie set:0xa
  0x3,       // ba_addr_driving;   //nt,pt, 0x214  //Stevie set:0xa
  0x50,       //uint8_t dq_driving;   //smt[0],sden[1],pd[2], e2[3], nt[5:4],pt[7:6], 0x218
  0x11111111,         // rx_delay_tap_0;  //bit 0 ~ 3, rising, default 0x10101010, 0x28c //Stevie set 0x15111611
  0x11111111,         // rx_delay_tap_1;  //bit 4 ~ 7, rising, default 0x10101010 , 0x29c //Stevie set 0x12141216
  0x11111111,         // rx_delay_tap_3;  //bit 8 ~ 11, rising, default 0x10101010, 0x290 //Stevie set 0x13121413
  0x11111111,         // rx_delay_tap_4;  //bit 12 ~ 15, rising, default 0x10101010 , 0x2a0 //Stevie set 0x13131213
  0x11111111,         // rx_delay_tap_0;  //bit 0 ~ 3, falling, default 0x10101010, 0x2ac //Stevie set 0x14111511
  0x11111111,         // rx_delay_tap_1;  //bit 4 ~ 7, falling, default 0x10101010 , 0x2bc //Stevie set 0x11141115
  0x11111111,         // rx_delay_tap_3;  //bit 8 ~ 11, falling, default 0x10101010, 0x2b0 //Stevie set 0x12111312
  0x11111111,         // rx_delay_tap_4;  //bit 12 ~ 15, falling, default 0x10101010 , 0x2c0 //Stevie set 0x13131312
  0x44444444,         //bit 0 ~ 7, default 0x33333333, 0x26c, original0x33333333
  0x44444444,         //bit 8 ~ 15, default 0x33333333, 0x270, original0x33333333
  0x44444444,         //bit 0 ~ 7, default 0x33333333, 0x27c, original0x33333333
  0x44444444,         //bit 8 ~ 15, default 0x33333333, 0x280, original0x33333333
  0x66666666,         // tx_delay_tap_0;  // bit 0 ~ 7, default 0x44444444     //mask also needs to be modified in dram_init_dpi_ip_ASIC.
  0x66666666,         // tx_delay_tap_1;   // bit 8 ~ 15, default 0x44444444  //mask also needs to be modified in dram_init_dpi_ip_ASIC.
  0x6464,         // dqs_dm_delay_tap; bit 15~0 dm: bit 7~4 bit 12~15 , default 0x4444  loca:0x240
};
#endif

const struct dram_device_info ddr2_800_dram_discret_info = {
  &ddr2_dram_M14D5121632A_dev,
  &ddr2_800_dram_discret_mode_reg,
  &ddr2_800_dram_M14D5121632A_timing,
  &ddr2_phy_discret_800,
  2540,          // ddr_period_ps, DDR2= 800
  (enum     dfi_ratio_type     *)DFI_RATIO_1
};

const struct dram_device_info ddr2_1066_dram_discret_info = {
  &ddr2_dram_M14D5121632A_dev,
  &ddr2_1066_dram_discret_mode_reg,
  &ddr2_1066_dram_M14D5121632A_timing,
  &ddr2_phy_discret_800,
  1876,          // ddr_period_ps, DDR2= 1066 1876 
  (enum     dfi_ratio_type     *)DFI_RATIO_1
};
#endif

#endif // not assembly
#endif //_MS_DRAM_PARA_H
 
