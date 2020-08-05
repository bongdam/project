/*
 * Davolink specific codes for following functions (since 2016.06)
 *
 * 1. Display current tx power of each rate and bandwidth
 * 2. Can modify tx power on-the-fly
 * 3. Display receive sensitivity parameters
 * 4. Can modify tx power on-the-fly
 *
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/netdevice.h>
#include <linux/init.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <net/udp.h>
#include <net/tcp.h>
#include <net/icmp.h>
#include <net/route.h>
#include <linux/netdevice.h>
#include <linux/ctype.h>

#ifdef __DRAYTEK_OS__
# include <draytek/wl_dev.h>
#endif

#include "./8192cd_cfg.h"
#include "./8192cd.h"
#include "./8192cd_hw.h"
#include "./8192cd_headers.h"
#include "./8192cd_debug.h"

#ifndef __KERNEL__
# include "./sys-support.h"
#endif

#ifdef RTL8190_VARIABLE_USED_DMEM
# include "./8192cd_dmem.h"
#endif

#include "8192cd_davo_wlan.h"

#include "dv_wlist.h"
#include <dvflag.h>

#include "8192cd_davo_wlcmd.h"

/*--------------------------------------------------------------------------*/
#ifndef __DAVO__
# error __DAVO__ is not defined!!
#endif

#define WL_LOG_SIZE		200
#define WL_LOG_MAX_LEN	100

#define read_pwr_reg(r)		cpu_to_le32(RTL_R32((r)))
#define write_pwr_reg(r,v)	RTL_W32((r), cpu_to_le32(v))

#define str2rate(s)			str2ddbm((s), NULL)
#define rate2str(r,b,l)		ddbm2str((unsigned char)(r),(b),(l))

#define get_wl_from_priv(a) ((wl_info_t *)&g_wl_info[((a)->pshare->wlandev_idx&1)])

/*
 * manipulation of psta->current_tx_rate of get_tx_rate()
 */
#define WLCMD_TX_RATE_PLUS 	0x1000
#define WLCMD_TX_RATE_MINUS 0x2000

/*--------------------------------------------------------------------------*/
/*
 * Function Prototype & Variables
 */
/*--------------------------------------------------------------------------*/
enum _cmd_type {
	WL_CMD_NULL,
	WL_CMD_UINT_VAR,
	WL_CMD_SET_RATE,
	WL_CMD_SET_DUMP_MODE,
	WL_CMD_SET_TXPOWER,
	WL_CMD_SET_ADDR,
	WL_CMD_SEND_TEST_FRAME,
	WL_CMD_SET_TX_RATE,
	WL_CMD_LAST,
};

enum _operation_mode {
	WL_OP_MODE_NONE,
	WL_OP_HELP,
	WL_OP_CURPOWER,
	WL_OP_TX_FRAME_STAT,
	WL_OP_FRAME_SUBTYPE,
	WL_OP_FRAME_LEN,
	WL_OP_FRAME_RATE,
	WL_OP_FRAME_QNUM,
	WL_OP_FRAME_SA,
	WL_OP_FRAME_DA,
	WL_OP_FRAME_BSSID,
	WL_OP_DUMP,
	WL_OP_LOG_FLAG,
	WL_OP_LOG_AID,
	WL_OP_TX_ANT,
	WL_OP_RX_ANT,
	WL_OP_BI,
	WL_OP_BCN_EN,
	WL_OP_TX_RATE,
	WL_OP_DATARTYLMT,
	WL_OP_MODE_LAST,
};

enum {
	WL_KIND_CCK,
	WL_KIND_OFDM,
	WL_KIND_MCS,
	WL_KIND_VHT,
};

enum {
	WL_DUMP_DEFAULT,
	WL_DUMP_LIST,
	WL_DUMP_BSS,
	WL_DUMP_STA,
	WL_DUMP_LOG,
	WL_DUMP_WALK_DBG,
	WL_DUMP_RXPKT_STATS,
};

typedef unsigned int uint32;

typedef union _reg_v {
	uint32 ui;
	unsigned char uc[4];
	signed char sc[4];
} reg_v_t;

// array depth: path (A/B), nss (1-2), group (MCS0-MCS9)
typedef struct _pwr_v {
	reg_v_t cck[2][1][1];	// cck[0][0][0] = Path-A, 1-11Mbps
	reg_v_t ofdm[2][1][2];	// ofdm[1][1][0] = Path-B, 24-54Mbps
	reg_v_t mcs[2][2][2];	// mcs[1][1][0] = Path-B, MCS8-MCS11
	reg_v_t vht[2][2][3];	// vht[0][1][2] = Path-A, NSS-2, MCS8-9
} pwr_v_t;

enum {
	WL_PATH_A,
	WL_PATH_B,
};

typedef struct _wl_txpwr {
	int band;		// 2, 5
	int channel;		// 1-14, 36-161
	int bw;			// 20,40,80,160
	int nss;		// 1-4
	unsigned char cal_ref_cck[2];	// reference calibration value
	unsigned char cal_ref_ht40[2];	// reference calibration value
	unsigned char cal_left_cck[2][4];	// calibration value of left 4 channels
	unsigned char cal_left_ht40[2][4];	// calibration value of left 4 channels
	unsigned char cal_right_cck[2][4];	// calibration value of right 4 channels
	unsigned char cal_right_ht40[2][4];	// calibration value of right 4 channels
	pwr_v_t cfg;		// configuration, saved value
	pwr_v_t reg;		// real register value
	pwr_v_t dbm;		// caculate to dBm
} wl_txpwr_t;

#define WL_WALK_DBG_BUF_SIZE	50
typedef struct _wl_walk_dbg {
	char pos[80];
	int lineno;
	int refcnt;
} wl_walk_dbg_t;

typedef struct _wl_info {
	struct rtl8192cd_priv *priv;
	unsigned int op_mode;
	unsigned int dump_mode;
	struct {
		unsigned char sa[MACADDRLEN];
		unsigned char da[MACADDRLEN];
		unsigned char bssid[MACADDRLEN];
		unsigned int subtype;
		unsigned int qnum;
		unsigned int rate;;
		int len;
		unsigned int tx_succ_cnt;
		unsigned int tx_fail_cnt;
	} test_frame;
	struct {
		char buf[WL_LOG_SIZE][WL_LOG_MAX_LEN];	/* message buffer */
		unsigned int ts[WL_LOG_SIZE];	/* timestamp of message */
		unsigned int flag;	/* b1: rssi, b2: tx status report, b3: print to console */
		int index;	/* head */
		int aid;	/* station filter */
	} log;
	unsigned int ant_save[2];	/* 0: tx, 1: rx */
	unsigned int bcn_ctrl_save;
	unsigned int force_tx_rate;
	unsigned int tx_rate_cnt;
#ifdef DV_WLCMD_DEBUG_COUNT
	wl_walk_dbg_t walk_dbg[WL_WALK_DBG_BUF_SIZE];
#endif
	unsigned int tx_retry_limit;
} wl_info_t;

typedef struct _cmd_tbl cmd_tbl_t;
typedef int (*cmd_fn_t)(void *handle, cmd_tbl_t *tbl, int argc, char *argv[]);

struct _cmd_tbl {
	const char *name;
	uint32 cmd_type;
	uint32 oper_mode;
	cmd_fn_t cmd_fn;
	const char *desc;
};

static int wl_cmd_open(struct inode *inode, struct file *file);
static ssize_t wl_cmd_write(struct file *file, const char __user *userbuf, size_t count, loff_t *off);

struct file_operations wl_cmd_fops = {
	.open = wl_cmd_open,
	.read = seq_read,
	.write = wl_cmd_write,
	.llseek = seq_lseek,
	.release = single_release
};

static wl_info_t g_wl_info[2];

/*--------------------------------------------------------------------------*/
static int wl_dump_help(struct rtl8192cd_priv *priv, wl_info_t *wl, struct seq_file *s);
static int wl_dump_curpower(struct rtl8192cd_priv *priv, wl_info_t *wl, struct seq_file *s);
static int wl_dump_bss(wl_info_t *wl, struct seq_file *s);
static int wl_dump_log(wl_info_t *wl, struct seq_file *s, int count);
static int wl_dump_walk_dbg(wl_info_t *wl, struct seq_file *s);
static int wl_dump_default(wl_info_t *wl, struct seq_file *s);
static int wl_dump_rxpkt_stats(wl_info_t *wl, struct seq_file *s);

/*--------------------------------------------------------------------------*/
#define TXPWR_HELP  "\ttxpwr <path> <rate> <dbm>\n\t\trate: cck0~3, ofdm0~7, mcs0~15, vht1-0~vht2-9\n" \
					"\t\tdbm: ex) 17.5"
#define DUMP_FLAG_HELP	"set dump flag(bit mask)\n" \
						"\t\t(0x01: sta rssi, 0x02: tx status, 0x04: to console)"
#define FRAME_RATE_HELP	"set tx rate of test frame\n" \
						"\t\t(1,2,...,54Mbps,mcs0,...,mcs15,vht1-0,...,vht2-9)"
#define ANT_SEL_HELP	"(b1:path-0(8814:B), b2:path-1(8814:C))\n" \
						"\t\t-1: set to default, -r <val>: set reg value directly"

static int wl_cmd_set_txpower(void *handle, cmd_tbl_t *tbl, int argc, char **argv);
static int wl_cmd_send_test_frame(void *handle, cmd_tbl_t *tbl, int argc, char **argv);

static cmd_tbl_t wl_cmd_table[] = {
	{"help", WL_CMD_UINT_VAR, WL_OP_HELP, NULL, "display this help"},
	{"curpower", WL_CMD_UINT_VAR, WL_OP_CURPOWER, NULL, "print current tramsmit power"},
	{"txpwr", WL_CMD_SET_TXPOWER, 0, wl_cmd_set_txpower, TXPWR_HELP},
	{"frame_subtype", WL_CMD_UINT_VAR, WL_OP_FRAME_SUBTYPE, NULL, "set subtype of test frame"},
	{"frame_len", WL_CMD_UINT_VAR, WL_OP_FRAME_LEN, NULL, "set subtype of test frame"},
	{"frame_rate", WL_CMD_SET_RATE, WL_OP_FRAME_RATE, NULL, FRAME_RATE_HELP},
	{"frame_qnum", WL_CMD_UINT_VAR, WL_OP_FRAME_QNUM, NULL, "set tx q number of test frame"},
	{"frame_sa", WL_CMD_SET_ADDR, WL_OP_FRAME_SA, NULL, "source address of test frame"},
	{"frame_da", WL_CMD_SET_ADDR, WL_OP_FRAME_DA, NULL, "destination address of test frame"},
	{"frame_bssid", WL_CMD_SET_ADDR, WL_OP_FRAME_BSSID, NULL, "bssid of test frame"},
	{"frame_send", WL_CMD_SEND_TEST_FRAME, WL_OP_TX_FRAME_STAT, wl_cmd_send_test_frame, "send test frame"},
	{"dump", WL_CMD_SET_DUMP_MODE, WL_OP_DUMP, NULL, "\tdump log message"},
	{"log_flag", WL_CMD_UINT_VAR, WL_OP_LOG_FLAG, NULL, DUMP_FLAG_HELP},
	{"log_aid", WL_CMD_UINT_VAR, WL_OP_LOG_AID, NULL, "set station aid filter of dump log"},
	{"txant", WL_CMD_UINT_VAR, WL_OP_TX_ANT, NULL, "\tset tx antenna path" ANT_SEL_HELP},
	{"rxant", WL_CMD_UINT_VAR, WL_OP_RX_ANT, NULL, "\tset rx antenna path" ANT_SEL_HELP},
	{"bi", WL_CMD_UINT_VAR, WL_OP_BI, NULL, "\tset beacon interval"},
	{"bcn_enable", WL_CMD_UINT_VAR, WL_OP_BCN_EN, NULL, "set beacon enable"},
	{"txrate", WL_CMD_SET_TX_RATE, WL_OP_TX_RATE, NULL, "set tx rate"},
	{"retry_limit", WL_CMD_UINT_VAR, WL_OP_DATARTYLMT, NULL, "set tx data retry limit"},
	{NULL, 0, 0, NULL, NULL}
};

/*--------------------------------------------------------------------------*/
/*
 * Local Functions
 */
/*--------------------------------------------------------------------------*/
static unsigned char calc_dbm(unsigned char val, unsigned char ref_val)
{
	unsigned char dbm = 17 * 2;

	dbm = dbm + val - ref_val;
	return (dbm);
}

static char *ddbm2str(unsigned char val, char *buf, int sz)
{
	snprintf(buf, sz, "%d%s", val / 2, (val & 1) ? ".5" : "");
	return (buf);
}

static uint32 str2ddbm(char *buf, int *sign)
{
	char *p, *s = buf;
	unsigned int ddbm;

	if (sign != NULL) {
		if (*s == '+') {
			*sign = 1;
			s++;
		} else if (*s == '_') {
			*sign = -1;
			s++;
		} else {
			*sign = 0;
		}
	}
	ddbm = simple_strtoul(s, &p, 10) * 2;
	if (p != NULL && *p == '.' && *(p + 1) >= '5' && *(p + 1) <= '9') {
		ddbm += 1;
	}
	return (ddbm);
}

static unsigned int os_msec(void)
{
	unsigned int ms = jiffies * (1000 / HZ);
	return (ms);
}

/*--------------------------------------------------------------------------*/
const unsigned int reg_ant_5g[2][4] = { {0, 0x2, 0x4, 0x106}, {0, 0x22, 0x44, 0x66} };
const unsigned int reg_ant_2g[2][4] = { {0, 0x8, 0x4, 0xc}, {0, 0x1, 0x5, 0x1} };

static unsigned int get_current_tx_ant(struct rtl8192cd_priv *priv, unsigned int *cfg)
{
	unsigned int i, val = 0;

	if ((GET_CHIP_VER(priv) == VERSION_8814A)) {
		// refer to Switch_Antenna_8814() in 8192cd_hw.c
		val = PHY_QueryBBReg(priv, 0x93c, 0xfff00000);
		if (cfg != NULL) {
			for (i = 0; i < 4; i++) {
				if (reg_ant_5g[0][i] == val) {
					*cfg = i;
					break;
				}
			}
		}
	} else if ((GET_CHIP_VER(priv) == VERSION_8192E)) {
		// refer to int Switch_Antenna_92E() in 8192cd_hw.c
		val = PHY_QueryBBReg(priv, 0xa04, 0xf0000000);
		if (cfg != NULL) {
			for (i = 0; i < 4; i++) {
				if (reg_ant_2g[0][i] == val) {
					*cfg = i;
					break;
				}
			}
		}
	}
	return (val);
}

static unsigned int get_current_rx_ant(struct rtl8192cd_priv *priv, unsigned int *cfg)
{
	unsigned int i, val = 0;

	if ((GET_CHIP_VER(priv) == VERSION_8814A)) {
		// refer to Switch_Antenna_8814() in 8192cd_hw.c
		val = PHY_QueryBBReg(priv, 0x808, 0xff);
		if (cfg != NULL) {
			for (i = 0; i < 4; i++) {
				if (reg_ant_5g[1][i] == val) {
					*cfg = i;
					break;
				}
			}
		}
	} else if ((GET_CHIP_VER(priv) == VERSION_8192E)) {
		// refer to int Switch_Antenna_92E() in 8192cd_hw.c
		val = PHY_QueryBBReg(priv, 0xa04, 0x0f000000);
		if (cfg != NULL) {
			for (i = 3; i > 0; i--) {
				if (reg_ant_2g[1][i] == val) {
					*cfg = i;
					break;
				}
			}
		}
	}
	return (val);
}

static void set_current_tx_ant(struct rtl8192cd_priv *priv, unsigned int val)
{
	if ((GET_CHIP_VER(priv) == VERSION_8814A)) {
		// refer to Switch_Antenna_8814() in 8192cd_hw.c
		PHY_SetBBReg(priv, 0x93c, 0xfff00000, val);
	} else if ((GET_CHIP_VER(priv) == VERSION_8192E)) {
		// refer to int Switch_Antenna_92E() in 8192cd_hw.c
		PHY_SetBBReg(priv, 0xa04, 0xf0000000, val);
	}
}

static void set_current_rx_ant(struct rtl8192cd_priv *priv, unsigned int val)
{
	if ((GET_CHIP_VER(priv) == VERSION_8814A)) {
		// refer to Switch_Antenna_8814() in 8192cd_hw.c
		PHY_SetBBReg(priv, 0x808, 0xff, val);
	} else if ((GET_CHIP_VER(priv) == VERSION_8192E)) {
		// refer to int Switch_Antenna_92E() in 8192cd_hw.c
		PHY_SetBBReg(priv, 0xa04, 0x0f000000, val);
	}
}

/*
static void print_current_antenna_regs(struct rtl8192cd_priv *priv, struct seq_file *s)
{
	if ((GET_CHIP_VER(priv)==VERSION_8814A)) {
		seq_printf(s, "8814A\n");
		seq_printf(s, "BB-REG 0x%x/0x%x = 0x%x\n", 0x93c, 0xfff00000,
						PHY_QueryBBReg(priv, 0x93c, 0xfff00000));
		seq_printf(s, "BB-REG 0x%x/0x%x = 0x%x\n", 0x808, 0xff,
						PHY_QueryBBReg(priv, 0x808, 0xff));
	} else if ((GET_CHIP_VER(priv)==VERSION_8192E)) {
		seq_printf(s, "8192E\n");
		seq_printf(s, "BB-REG 0x%x/0x%x = 0x%x\n", 0xa04, 0xff000000,
						PHY_QueryBBReg(priv, 0xa04, 0xff000000));
	}
}

static int check_rate_ant(struct rtl8192cd_priv *priv, unsigned int tx_rate)
{
	unsigned int val, cfg;

	val = get_current_rx_ant(priv, &cfg);

	if (cfg != 3 && tx_rate >= _MCS0_RATE_)
		return 0;

	return (1);
}
*/

static int wl_cmd_ant_select(wl_info_t *wl, uint32 oper_mode, int argc, char *argv[])
{
	struct rtl8192cd_priv *priv = wl->priv;
	int dir;
	unsigned int val, reg_val;

	if (oper_mode == WL_OP_TX_ANT)
		dir = 0;
	else
		dir = 1;

	if (argc > 2 && !strcmp(argv[1], "-r")) {
		reg_val = simple_strtoul(argv[2], NULL, 0);
	} else {
		val = simple_strtoul(argv[1], NULL, 0);
		if (val > 3)
			return (-1);
		if (val <= 0) {
			if (wl->ant_save[dir] != 0) {
				if (!dir)
					set_current_tx_ant(priv, wl->ant_save[dir]);
				else
					set_current_rx_ant(priv, wl->ant_save[dir]);
				return (0);
			}
		}
		if ((GET_CHIP_VER(priv) == VERSION_8814A)) {
			reg_val = reg_ant_5g[dir][val];
		} else {
			reg_val = reg_ant_2g[dir][val];
		}
	}
	if (!wl->ant_save[dir]) {
		wl->ant_save[dir] = (!dir) ? get_current_tx_ant(priv, NULL) : get_current_rx_ant(priv, NULL);
	}
	set_current_tx_ant(priv, reg_val);
	return (0);
}

/*--------------------------------------------------------------------------*/
static char *get_current_channel_str(struct rtl8192cd_priv *priv, char *buf, int bufsz)
{
	if (priv->pshare->is_40m_bw == 2)
		snprintf(buf, bufsz, "%u/80", priv->pmib->dot11RFEntry.dot11channel);
	else if (priv->pshare->is_40m_bw == 1) {
		if (priv->pmib->dot11nConfigEntry.dot11n2ndChOffset == 2)
			snprintf(buf, bufsz, "%uL", priv->pmib->dot11RFEntry.dot11channel);
		else if (priv->pmib->dot11nConfigEntry.dot11n2ndChOffset == 1)
			snprintf(buf, bufsz, "%uU", priv->pmib->dot11RFEntry.dot11channel);
		else
			snprintf(buf, bufsz, "%u/40", priv->pmib->dot11RFEntry.dot11channel);
	} else {
		snprintf(buf, bufsz, "%u", priv->pmib->dot11RFEntry.dot11channel);
	}

	return buf;
}

/*--------------------------------------------------------------------------*/
static void wl_cmd_set_beacon_interval(wl_info_t *wl, uint32 val)
{
	struct rtl8192cd_priv *priv = wl->priv;

	if (val >= 20)
		RTL_W32(MBSSID_BCN_SPACE, val);
}

static unsigned int wl_cmd_get_beacon_interval(wl_info_t *wl)
{
	struct rtl8192cd_priv *priv = wl->priv;

	unsigned int val = RTL_R32(MBSSID_BCN_SPACE) & BCN_SPACE1_Mask;

	return (val);
}

static void wl_cmd_set_beacon_enable(wl_info_t *wl, uint32 enable)
{
	struct rtl8192cd_priv *priv = wl->priv;
	unsigned char val;
	int i;

	val = RTL_R8(BCN_CTRL);
	if (enable && !val) {
		if (wl->bcn_ctrl_save) {
			RTL_W8(BCN_CTRL, (unsigned char)wl->bcn_ctrl_save);
		}
		GET_ROOT(priv)->pmib->miscEntry.func_off = 0;
#if defined(MBSSID)
		for (i = 0; i < RTL8192CD_NUM_VWLAN; i++) {
			if (IS_DRV_OPEN(GET_ROOT(priv)->pvap_priv[i])) {
				(GET_ROOT(priv)->pvap_priv[i])->pmib->miscEntry.func_off = 0;
			}
		}
#endif
	} else if (!enable && val) {
		RTL_W8(BCN_CTRL, 0);
		wl->bcn_ctrl_save = val;
		GET_ROOT(priv)->pmib->miscEntry.func_off = 1;
#if defined(MBSSID)
		for (i = 0; i < RTL8192CD_NUM_VWLAN; i++) {
			if (IS_DRV_OPEN(GET_ROOT(priv)->pvap_priv[i])) {
				(GET_ROOT(priv)->pvap_priv[i])->pmib->miscEntry.func_off = 1;
			}
		}
#endif
	}
}

static unsigned int wl_cmd_get_beacon_enable(wl_info_t *wl)
{
	struct rtl8192cd_priv *priv = wl->priv;

	unsigned char val = RTL_R8(BCN_CTRL);

	return (! !val);
}

/*--------------------------------------------------------------------------*/
/*
 *	command processing
 */
/*--------------------------------------------------------------------------*/
static int wl_cmd_uint_var(wl_info_t *wl, uint32 oper_mode, int argc, char *argv[])
{
	int ret = 0;
	unsigned int val;

	wl->op_mode = oper_mode;

	if (argc < 2)
		return (ret);

	val = simple_strtoul(argv[1], NULL, 0);

	switch (oper_mode) {
	case WL_OP_FRAME_SUBTYPE:
		wl->test_frame.subtype = val;
		break;
	case WL_OP_FRAME_LEN:
		wl->test_frame.len = val;
		break;
	case WL_OP_FRAME_QNUM:
		wl->test_frame.qnum = val;
		break;
	case WL_OP_LOG_FLAG:
		wl->log.flag = val;
		break;

	case WL_OP_LOG_AID:
		wl->log.aid = val;
		break;

	case WL_OP_TX_ANT:
	case WL_OP_RX_ANT:
		ret = wl_cmd_ant_select(wl, oper_mode, argc, argv);
		break;

	case WL_OP_BI:
		wl_cmd_set_beacon_interval(wl, val);
		break;

	case WL_OP_BCN_EN:
		wl_cmd_set_beacon_enable(wl, val);
		break;

	case WL_OP_DATARTYLMT:
		wl->tx_retry_limit = val;
		break;

	default:
		ret = -1;
		break;
	}
	return (ret);
}

static int wl_cmd_set_rate(wl_info_t *wl, uint32 oper_mode, int argc, char *argv[])
{
	unsigned int nss, tx_rate = 0;
	char *p;

	wl->op_mode = oper_mode;

	if (argc < 2)
		return (0);

	if (!strncmp(argv[1], "mcs", 3)) {
		tx_rate = _MCS0_RATE_ + simple_strtoul(argv[1] + 3, NULL, 10);
		if (tx_rate < _MCS0_RATE_ || tx_rate > _MCS15_RATE_)
			return (-1);
	} else if (!strncmp(argv[1], "vht", 3)) {
		nss = simple_strtoul(argv[1] + 3, &p, 10) - 1;
		if (p != NULL) {
			tx_rate = simple_strtoul(p + 1, NULL, 10) + _NSS1_MCS0_RATE_ + nss * 10;
		}
		if (tx_rate < _NSS1_MCS0_RATE_ || tx_rate > _NSS2_MCS9_RATE_)
			return (-1);
	} else {
		tx_rate = str2rate(argv[1]);
		if (!is_CCK_rate((unsigned char)tx_rate) && !is_OFDM_rate((unsigned char)tx_rate))
			return (-1);
	}

	wl->test_frame.rate = tx_rate;
	return (0);
}

/*--------------------------------------------------------------------------*/
static int wl_cmd_fn_default(void *handle, cmd_tbl_t *tbl, int argc, char *argv[])
{
	wl_info_t *wl = (wl_info_t *) handle;
	int ret = 0;

	switch (tbl->cmd_type) {
	case WL_CMD_SET_DUMP_MODE:
		wl->op_mode = tbl->oper_mode;
		if (argc > 1) {
			if (!strcmp(argv[1], "sta"))
				wl->dump_mode = WL_DUMP_STA;
			else if (!strcmp(argv[1], "list"))
				wl->dump_mode = WL_DUMP_LIST;
			else if (!strcmp(argv[1], "bss"))
				wl->dump_mode = WL_DUMP_BSS;
			else if (!strcmp(argv[1], "log"))
				wl->dump_mode = WL_DUMP_LOG;
#ifdef DV_WLCMD_DEBUG_COUNT
			else if (!strcmp(argv[1], "walk"))
				wl->dump_mode = WL_DUMP_WALK_DBG;
#endif
			else if (!strcmp(argv[1], "rxpkt"))
				wl->dump_mode = WL_DUMP_RXPKT_STATS;
			else
				wl->dump_mode = WL_DUMP_DEFAULT;
		} else {
			wl->dump_mode = WL_DUMP_DEFAULT;
		}
		break;

	case WL_CMD_UINT_VAR:
		ret = wl_cmd_uint_var(wl, tbl->oper_mode, argc, argv);
		break;

	case WL_CMD_SET_RATE:
		ret = wl_cmd_set_rate(wl, tbl->oper_mode, argc, argv);
		break;

	case WL_CMD_SET_ADDR:
		if (argc > 1) {
			unsigned char *ea;
			switch (tbl->oper_mode) {
			case WL_OP_FRAME_SA:
				ea = wl->test_frame.sa;
				break;
			case WL_OP_FRAME_DA:
				ea = wl->test_frame.da;
				break;
			case WL_OP_FRAME_BSSID:
				ea = wl->test_frame.bssid;
				break;
			default:
				return (-1);
			}
			if (h_atoe(argv[1], ea))
				ret = -1;
		} else {
			wl->op_mode = tbl->oper_mode;
		}
		break;

	case WL_CMD_SET_TX_RATE:
		if (argc > 1) {
			unsigned int nss, tx_rate = 0;
			if (*argv[1] == '+') {
				tx_rate = simple_strtoul(argv[1] + 1, NULL, 10);
				tx_rate |= WLCMD_TX_RATE_PLUS;
			} else if (*argv[1] == '_') {
				tx_rate = simple_strtoul(argv[1] + 1, NULL, 10);
				tx_rate |= WLCMD_TX_RATE_MINUS;
			} else {
				char *p;
				if (!strncmp(argv[1], "mcs", 3)) {
					tx_rate = _MCS0_RATE_ + simple_strtoul(argv[1] + 3, NULL, 10);
					if (tx_rate < _MCS0_RATE_ || tx_rate > _MCS15_RATE_)
						return (-1);
				} else if (!strncmp(argv[1], "vht", 3)) {
					nss = simple_strtoul(argv[1] + 3, &p, 10) - 1;
					if (p != NULL) {
						tx_rate = simple_strtoul(p + 1, NULL, 10) + _NSS1_MCS0_RATE_ + nss * 10;
					}
					if (tx_rate < _NSS1_MCS0_RATE_ || tx_rate > _NSS2_MCS9_RATE_)
						return (-1);
				} else {
					tx_rate = str2rate(argv[1]);
					if (tx_rate != 0 &&
					    !is_CCK_rate((unsigned char)tx_rate) && !is_OFDM_rate((unsigned char)tx_rate))
						return (-1);
				}
			}
			wl->force_tx_rate = tx_rate;
		} else {
			wl->op_mode = tbl->oper_mode;
		}

	default:
		ret = -1;
		break;
	}

	return (ret);
}

static int wl_cmd_process(void *handle, char *buf)
{
	char *argv[20];
	int argc, ret = -1;
	cmd_tbl_t *tbl;

	argc = strargs(buf, argv, 20, " \t\n\r");

	if (argc < 1) {
		return (-1);
	}

	for (tbl = wl_cmd_table; tbl != NULL && tbl->name != NULL; tbl++) {
		if (!strcmp(tbl->name, argv[0])) {
			if (tbl->cmd_fn != NULL) {
				ret = tbl->cmd_fn(handle, tbl, argc, argv);
			} else {
				ret = wl_cmd_fn_default(handle, tbl, argc, argv);
			}
			break;
		}
	}

	return (ret);
}

/*--------------------------------------------------------------------------*/
static int wl_dump_process(struct seq_file *s, void *data)
{
	wl_info_t *wl = (wl_info_t *) (s->private);
	struct rtl8192cd_priv *priv = wl->priv;
	char buf[40];
	int ret = 0;
	unsigned int val, cfg;

	if (wl == NULL) {
		seq_printf(s, "no information\n");
		return (0);
	}
	switch (wl->op_mode) {
	case WL_OP_HELP:
		ret = wl_dump_help(priv, wl, s);
		break;

	case WL_OP_CURPOWER:
		ret = wl_dump_curpower(priv, wl, s);
		break;

	case WL_OP_FRAME_SUBTYPE:
		seq_printf(s, "0x%x\n", wl->test_frame.subtype);
		break;

	case WL_OP_FRAME_LEN:
		seq_printf(s, "%u\n", wl->test_frame.len);
		break;

	case WL_OP_FRAME_RATE:
		if (wl->test_frame.rate >= _NSS1_MCS0_RATE_) {
			unsigned int rate = wl->test_frame.rate - _NSS1_MCS0_RATE_;
			seq_printf(s, "vht%d-%d(0x%x)\n", rate / 10 + 1, rate % 10, wl->test_frame.rate);
		} else if (wl->test_frame.rate >= _MCS0_RATE_) {
			seq_printf(s, "mcs%d(0x%x)\n", wl->test_frame.rate - _MCS0_RATE_, wl->test_frame.rate);
		} else {
			seq_printf(s, "%sMbps\n", rate2str(wl->test_frame.rate, buf, sizeof(buf)));
		}
		break;

	case WL_OP_FRAME_QNUM:
		seq_printf(s, "0x%x\n", wl->test_frame.qnum);
		break;

	case WL_OP_FRAME_SA:
		seq_printf(s, "%pM\n", wl->test_frame.sa);
		break;

	case WL_OP_FRAME_DA:
		seq_printf(s, "%pM\n", wl->test_frame.da);
		break;

	case WL_OP_FRAME_BSSID:
		seq_printf(s, "%pM\n", wl->test_frame.bssid);
		break;

	case WL_OP_TX_FRAME_STAT:
		seq_printf(s, "sa:\t%pM\n", wl->test_frame.sa);
		seq_printf(s, "da:\t%pM\n", wl->test_frame.da);
		seq_printf(s, "bssid:\t%pM\n", wl->test_frame.bssid);
		seq_printf(s, "subtype:\t0x%02x\n", wl->test_frame.subtype);
		seq_printf(s, "qnum:\t%u\n", wl->test_frame.qnum);
		seq_printf(s, "rate:\t0x%x\n", wl->test_frame.rate);
		val = get_current_tx_ant(priv, &cfg);
		seq_printf(s, "txant:\t%d(0x%x)\n", cfg, val);
		seq_printf(s, "len:\t%u\n", wl->test_frame.len);
		seq_printf(s, "\ntx success:\t%u\n", wl->test_frame.tx_succ_cnt);
		seq_printf(s, "tx fail:\t\t%u\n", wl->test_frame.tx_fail_cnt);
		break;

	case WL_OP_DUMP:
		ret = wl_dump_default(wl, s);
		break;

	case WL_OP_LOG_FLAG:
		seq_printf(s, "0x%x\n", wl->log.flag);
		break;

	case WL_OP_LOG_AID:
		seq_printf(s, "0x%x\n", wl->log.aid);
		break;

	case WL_OP_TX_ANT:
		val = get_current_tx_ant(priv, &cfg);
		seq_printf(s, "%d(0x%x)\n", cfg, val);
		//print_current_antenna_regs(priv, s);
		break;

	case WL_OP_RX_ANT:
		val = get_current_rx_ant(priv, &cfg);
		seq_printf(s, "%d(0x%x)\n", cfg, val);
		break;

	case WL_OP_BI:
		val = wl_cmd_get_beacon_interval(wl);
		seq_printf(s, "%d(0x%x)\n", val, val);
		break;

	case WL_OP_BCN_EN:
		val = wl_cmd_get_beacon_enable(wl);
		seq_printf(s, "%d\n", val);
		break;

	case WL_OP_TX_RATE:
		seq_printf(s, "0x%x %d\n", wl->force_tx_rate, wl->tx_rate_cnt);
		break;

	case WL_OP_DATARTYLMT:
		seq_printf(s, "0x%x\n", wl->tx_retry_limit);
		break;

	default:
		ret = -1;
		break;
	}

	return (ret);
}

/*--------------------------------------------------------------------------*/
static int wl_cmd_open(struct inode *inode, struct file *file)
{
	return single_open(file, wl_dump_process, PDE_DATA(file_inode(file)));
}

static int wl_cmd_write_real(struct file *file, const char *buffer, unsigned long count, void *data)
{
	int len;
	char *buf = kmalloc(count + 1, GFP_KERNEL);

	if (buf == NULL)
		return -ENOMEM;
	len = strtrim_from_user(buf, count + 1, buffer, count);
	if (len > 0) {
		wl_cmd_process(data, buf);
	}
	kfree(buf);
	return count;
}

static ssize_t wl_cmd_write(struct file *file, const char __user *userbuf, size_t count, loff_t *off)
{
	return wl_cmd_write_real(file, userbuf, count, PDE_DATA(file_inode(file)));
}

/*--------------------------------------------------------------------------*/
static int wl_dump_help(struct rtl8192cd_priv *priv, wl_info_t *wl, struct seq_file *s)
{
	cmd_tbl_t *tbl;

	for (tbl = wl_cmd_table; tbl != NULL && tbl->name != NULL; tbl++) {
		seq_printf(s, "%s:\t%s\n", tbl->name, (tbl->desc != NULL) ? tbl->desc : "");
	}
	return (0);
}

/*--------------------------------------------------------------------------*/
const char *cck_rate_str[4] = { "1Mbps", "2Mbps", "5.5Mbps", "11Mbps" };
const char *ofdm_rate_str[8] = { "6Mbps", "9Mbps", "12Mbps", "18Mbps", "24Mbps", "36Mbps", "48Mbps", "54Mbps" };

static char *str_rate(int kind, int nss, int group, int rate_index, char *buf, int sz)
{
	switch (kind) {
	case WL_KIND_CCK:
		snprintf(buf, sz, "CCK %s", cck_rate_str[rate_index % 4]);
		break;
	case WL_KIND_OFDM:
		snprintf(buf, sz, "OFDM %s", ofdm_rate_str[group * 4 + rate_index % 4]);
		break;
	case WL_KIND_MCS:
		snprintf(buf, sz, "HT MCS%d", (nss * 2 + group) * 4 + rate_index);
		break;
	case WL_KIND_VHT:
		snprintf(buf, sz, "VHT MCS%d NSS%d", group * 4 + rate_index, nss + 1);
		break;
	default:
		snprintf(buf, sz, "Unknown");
		break;
	}
	return (buf);
}

static void print_pwr(struct seq_file *s, wl_txpwr_t * pwr)
{
	int i, j, k, n, t;
	pwr_v_t *p, *q, *r;
	char name[20], b1[8], b2[8];

	seq_printf(s, "channel:\t%d\n", pwr->channel);
	seq_printf(s, "bandwidth:\t%dMHz\n\n", pwr->bw);
	seq_printf(s, "calibration(CCK): ");
	for (i = 0; i < 4; i++)
		seq_printf(s, " %02x|%02x", pwr->cal_left_cck[0][i], pwr->cal_left_cck[1][i]);
	seq_printf(s, "  %02x|%02x ", pwr->cal_ref_cck[0], pwr->cal_ref_cck[1]);
	for (i = 0; i < 4; i++)
		seq_printf(s, " %02x|%02x", pwr->cal_right_cck[0][i], pwr->cal_right_cck[1][i]);
	seq_printf(s, "\n");
	seq_printf(s, "calibration(HT40):");
	for (i = 0; i < 4; i++)
		seq_printf(s, " %02x|%02x", pwr->cal_left_ht40[0][i], pwr->cal_left_ht40[1][i]);
	seq_printf(s, "  %02x|%02x ", pwr->cal_ref_ht40[0], pwr->cal_ref_ht40[1]);
	for (i = 0; i < 4; i++)
		seq_printf(s, " %02x|%02x", pwr->cal_right_ht40[0][i], pwr->cal_right_ht40[1][i]);
	seq_printf(s, "\n\n");
	seq_printf(s, "%-16s %-3s %-6s %-3s   %-3s %-6s %-3s\n", "", "", "Path-0", "", "", "Path-1", "");
	seq_printf(s, "%-16s %-4s %-4s %-4s   %-4s %-4s %-4s\n", "rate", "dBm", "diff", "reg", "dBm", "diff", "reg");
	seq_printf(s, "%-16s %-4s %-4s %-4s   %-4s %-4s %-4s\n", "===============", "====", "====", "====", "====", "====",
		   "====");

	// i=path, j=nss, k=group, n=rate (6->9->12->18)
	p = &pwr->dbm;
	q = &pwr->cfg;
	r = &pwr->reg;
	if (p->cck[0][0][0].ui != 0) {
		for (n = 0; n < 4; n++) {
			seq_printf(s, "%-16s %-4s %-4d 0x%02x   %-4s %-4d 0x%02x\n",
				   str_rate(WL_KIND_CCK, 0, 0, n, name, sizeof(name)),
				   ddbm2str(p->cck[0][0][0].sc[n], b1, sizeof(b1)),
				   q->cck[0][0][0].sc[n],
				   r->cck[0][0][0].sc[n],
				   ddbm2str(p->cck[1][0][0].sc[n], b2, sizeof(b2)),
				   q->cck[1][0][0].sc[n], r->cck[1][0][0].sc[n]);
		}
		seq_printf(s, "-------------------------------------------------\n");
	}
	if (p->ofdm[0][0][0].ui != 0) {
		for (k = 0; k < 2; k++) {
			for (n = 0; n < 4; n++) {
				seq_printf(s, "%-16s %-4s %-4d 0x%02x   %-4s %-4d 0x%02x\n",
					   str_rate(WL_KIND_OFDM, 0, k, n, name, sizeof(name)),
					   ddbm2str(p->ofdm[0][0][k].sc[n], b1, sizeof(b1)),
					   q->ofdm[0][0][k].sc[n],
					   r->ofdm[0][0][k].sc[n],
					   ddbm2str(p->ofdm[1][0][k].sc[n], b2, sizeof(b2)),
					   q->ofdm[1][0][k].sc[n], r->ofdm[1][0][k].sc[n]);
			}
		}
		seq_printf(s, "-------------------------------------------------\n");
	}
	if (p->mcs[0][0][0].ui != 0) {
		for (j = 0; j < 2; j++) {
			for (k = 0; k < 2; k++) {
				for (n = 0; n < 4; n++) {
					seq_printf(s, "%-16s %-4s %-4d 0x%02x   %-4s %-4d 0x%02x\n",
						   str_rate(WL_KIND_MCS, j, k, n, name, sizeof(name)),
						   ddbm2str(p->mcs[0][j][k].sc[n], b1, sizeof(b1)),
						   q->mcs[0][j][k].sc[n],
						   r->mcs[0][j][k].sc[n],
						   ddbm2str(p->mcs[1][j][k].sc[n], b2, sizeof(b2)),
						   q->mcs[1][j][k].sc[n], r->mcs[1][j][k].sc[n]);
				}
			}
			seq_printf(s, "-------------------------------------------------\n");
		}
	}
	if (p->vht[0][0][0].ui != 0) {
		for (j = 0; j < 2; j++) {
			for (k = 0; k < 3; k++) {
				for (n = 0; n < 4; n++) {
					t = k * 4 + n;	// mcs0 - mcs9
					if (t < 10) {
						seq_printf(s, "%-16s %-4s %-4d 0x%02x   %-4s %-4d 0x%02x\n",
							   str_rate(WL_KIND_VHT, j, k, n, name, sizeof(name)),
							   ddbm2str(p->vht[0][j][k].sc[n], b1, sizeof(b1)),
							   q->vht[0][j][k].sc[n],
							   r->vht[0][j][k].sc[n],
							   ddbm2str(p->vht[1][j][k].sc[n], b2, sizeof(b2)),
							   q->vht[1][j][k].sc[n], r->vht[1][j][k].sc[n]);
					}
				}
			}
			seq_printf(s, "-------------------------------------------------\n");
		}
	}
}

static void get_pwr_of_8192e(struct rtl8192cd_priv *priv, wl_info_t *wl, wl_txpwr_t *pwr)
{
	int i, j, k, n;
	reg_v_t v;
	pwr_v_t *p, *q;

	// only 2 path, set reference calibration value set in mib_rf
	pwr->cal_ref_cck[0] = priv->pmib->dot11RFEntry.pwrlevelCCK_A[pwr->channel - 1];
	pwr->cal_ref_cck[1] = priv->pmib->dot11RFEntry.pwrlevelCCK_B[pwr->channel - 1];
	pwr->cal_ref_ht40[0] = priv->pmib->dot11RFEntry.pwrlevelHT40_1S_A[pwr->channel - 1];
	pwr->cal_ref_ht40[1] = priv->pmib->dot11RFEntry.pwrlevelHT40_1S_B[pwr->channel - 1];
	for (i = pwr->channel - 2, j = 0; i >= 0 && j < 4; i--, j++) {
		pwr->cal_left_cck[0][j] = priv->pmib->dot11RFEntry.pwrlevelCCK_A[i];
		pwr->cal_left_cck[1][j] = priv->pmib->dot11RFEntry.pwrlevelCCK_B[i];
		pwr->cal_left_ht40[0][j] = priv->pmib->dot11RFEntry.pwrlevelHT40_1S_A[i];
		pwr->cal_left_ht40[1][j] = priv->pmib->dot11RFEntry.pwrlevelHT40_1S_B[i];
	}
	for (i = pwr->channel, j = 0; i < 14 && j < 4; i++, j++) {
		pwr->cal_right_cck[0][j] = priv->pmib->dot11RFEntry.pwrlevelCCK_A[i];
		pwr->cal_right_cck[1][j] = priv->pmib->dot11RFEntry.pwrlevelCCK_B[i];
		pwr->cal_right_ht40[0][j] = priv->pmib->dot11RFEntry.pwrlevelHT40_1S_A[i];
		pwr->cal_right_ht40[1][j] = priv->pmib->dot11RFEntry.pwrlevelHT40_1S_B[i];
	}

	// read register and set them to structure
	p = &pwr->reg;
	// CCK
	v.ui = read_pwr_reg(0xe08);
	p->cck[0][0][0].uc[0] = v.uc[1];	// path-A, 1Mbps
	v.ui = read_pwr_reg(0x86c);
	p->cck[0][0][0].uc[1] = v.uc[1];	// path-A, 2Mbps
	p->cck[0][0][0].uc[2] = v.uc[2];	// path-A, 5.5Mbps
	p->cck[0][0][0].uc[3] = v.uc[3];	// path-A, 11Mbps

	p->cck[1][0][0].uc[3] = v.uc[0];	// path-B, 11Mbps
	v.ui = read_pwr_reg(0x838);
	p->cck[1][0][0].uc[0] = v.uc[1];	// path-B, 2Mbps
	p->cck[1][0][0].uc[1] = v.uc[2];	// path-B, 5.5Mbps
	p->cck[1][0][0].uc[2] = v.uc[3];	// path-B, 11Mbps

	// OFDM
	p->ofdm[0][0][0].ui = read_pwr_reg(0xe00);	// path-A, 6Mbps ~ 16Mbps
	p->ofdm[0][0][1].ui = read_pwr_reg(0xe04);	// path-A, 24Mbps ~ 54Mbps
	p->ofdm[1][0][0].ui = read_pwr_reg(0x830);	// path-B, 6Mbps ~ 16Mbps
	p->ofdm[1][0][1].ui = read_pwr_reg(0x834);	// path-B, 24Mbps ~ 54Mbps

	// MCS
	p->mcs[0][0][0].ui = read_pwr_reg(0xe10);	// path-A, MCS0 ~ MCS3
	p->mcs[0][0][1].ui = read_pwr_reg(0xe14);	// path-A, MCS4 ~ MCS7
	p->mcs[0][1][0].ui = read_pwr_reg(0xe18);	// path-A, MCS8 ~ MCS11
	p->mcs[0][1][1].ui = read_pwr_reg(0xe1c);	// path-A, MCS12 ~ MCS15
	p->mcs[1][0][0].ui = read_pwr_reg(0x83c);	// path-B, MCS0 ~ MCS3
	p->mcs[1][0][1].ui = read_pwr_reg(0x848);	// path-B, MCS4 ~ MCS7
	p->mcs[1][1][0].ui = read_pwr_reg(0x84c);	// path-B, MCS8 ~ MCS11
	p->mcs[1][1][1].ui = read_pwr_reg(0x868);	// path-B, MCS12 ~ MCS15

	// read priv structure and set them to structure
	// i=path, j=group, k=nss, n=rate(6->9->12->18)
	p = &pwr->cfg;
	for (n = 0; n < 4; n++) {
		p->cck[0][0][0].sc[n] = priv->pshare->phw->CCKTxAgc_A[n];	// path-A, 1Mbps ~ 11Mbps
		p->cck[1][0][0].sc[n] = priv->pshare->phw->CCKTxAgc_B[n];	// path-B, 1Mbps ~ 11Mbps
	}
	p->cck[0][0][0].ui = cpu_to_le32(p->cck[0][0][0].ui);
	p->cck[1][0][0].ui = cpu_to_le32(p->cck[1][0][0].ui);
	for (k = 0; k < 2; k++) {
		for (n = 0; n < 4; n++) {
			p->ofdm[0][0][k].sc[n] = priv->pshare->phw->OFDMTxAgcOffset_A[k * 4 + n];	// path-A
			p->ofdm[1][0][k].sc[n] = priv->pshare->phw->OFDMTxAgcOffset_B[k * 4 + n];	// path-B
		}
	}
	for (j = 0; j < 2; j++) {
		for (k = 0; k < 2; k++) {
			for (n = 0; n < 4; n++) {
				p->mcs[0][j][k].sc[n] = priv->pshare->phw->MCSTxAgcOffset_A[(j * 2 + k) * 4 + n];	// path-A
				p->mcs[1][j][k].sc[n] = priv->pshare->phw->MCSTxAgcOffset_B[(j * 2 + k) * 4 + n];	// path-B
			}
		}
	}

	// calculate to dBm, i=path, j=group, k=nss, n=rate (6->9->12->18)
	p = &pwr->dbm;
	q = &pwr->reg;
	for (i = 0; i < 2; i++) {
		for (n = 0; n < 4; n++) {
			p->cck[i][0][0].sc[n] = calc_dbm(q->cck[i][0][0].sc[n], pwr->cal_ref_cck[i]);
		}
		for (k = 0; k < 2; k++) {
			for (n = 0; n < 4; n++) {
				p->ofdm[i][0][k].sc[n] = calc_dbm(q->ofdm[i][0][k].sc[n], pwr->cal_ref_ht40[i]);
			}
		}
		for (j = 0; j < 2; j++) {
			for (k = 0; k < 2; k++) {
				for (n = 0; n < 4; n++) {
					p->mcs[i][j][k].sc[n] = calc_dbm(q->mcs[i][j][k].sc[n], pwr->cal_ref_ht40[i]);
				}
			}
		}
	}
}

static void get_pwr_of_8814a(struct rtl8192cd_priv *priv, wl_info_t *wl, wl_txpwr_t *pwr)
{
	int i, j, k, n, t;
	pwr_v_t *p, *q;

	// only 2 path, set reference calibration value set in mib_rf
	pwr->cal_ref_ht40[0] = priv->pmib->dot11RFEntry.pwrlevel5GHT40_1S_B[pwr->channel - 1];
	pwr->cal_ref_ht40[1] = priv->pmib->dot11RFEntry.pwrlevel5GHT40_1S_C[pwr->channel - 1];
	for (i = pwr->channel - 2, j = 0; i >= 36 && j < 4; i--, j++) {
		pwr->cal_left_ht40[0][j] = priv->pmib->dot11RFEntry.pwrlevel5GHT40_1S_B[i];
		pwr->cal_left_ht40[1][j] = priv->pmib->dot11RFEntry.pwrlevel5GHT40_1S_C[i];
	}
	for (i = pwr->channel, j = 0; i < 161 && j < 4; i++, j++) {
		pwr->cal_right_ht40[0][j] = priv->pmib->dot11RFEntry.pwrlevel5GHT40_1S_B[i];
		pwr->cal_right_ht40[1][j] = priv->pmib->dot11RFEntry.pwrlevel5GHT40_1S_C[i];
	}

	// cannot read real register value from 8814AE

	// read priv structure and set them to structure
	// i=path, j=group, k=nss, n=rate(6->9->12->18)
	p = &pwr->reg;
	for (i = 0; i < 2; i++) {
		for (k = 0; k < 2; k++) {
			for (n = 0; n < 4; n++) {
				p->ofdm[i][0][k].sc[n] = priv->pshare->phw->CurrentTxAgcOFDM[i + 1][k * 4 + n];	// path-B/C
			}
		}
		for (j = 0; j < 2; j++) {
			for (k = 0; k < 2; k++) {
				for (n = 0; n < 4; n++) {
					p->mcs[i][j][k].sc[n] = priv->pshare->phw->CurrentTxAgcMCS[i + 1][(j * 2 + k) * 4 + n];	// path-B/C
				}
			}
		}
		for (j = 0; j < 2; j++) {
			for (k = 0; k < 3; k++) {
				for (n = 0; n < 4; n++) {
					t = k * 4 + n;	// mcs0 - mcs9
					if (t < 10) {
						p->vht[i][j][k].sc[n] = priv->pshare->phw->CurrentTxAgcVHT[i + 1][j * 10 + t];	// path-B/C
					}
				}
			}
		}
	}

	// calculate to dBm, i=path, j=group, k=nss, n=rate (6->9->12->18)
	p = &pwr->dbm;
	q = &pwr->reg;
	for (i = 0; i < 2; i++) {
		for (k = 0; k < 2; k++) {
			for (n = 0; n < 4; n++) {
				p->ofdm[i][0][k].sc[n] = calc_dbm(q->ofdm[i][0][k].sc[n], pwr->cal_ref_ht40[i]);
			}
		}
		for (j = 0; j < 2; j++) {
			for (k = 0; k < 2; k++) {
				for (n = 0; n < 4; n++) {
					p->mcs[i][j][k].sc[n] = calc_dbm(q->mcs[i][j][k].sc[n], pwr->cal_ref_ht40[i]);
				}
			}
		}
		for (j = 0; j < 2; j++) {
			for (k = 0; k < 3; k++) {
				for (n = 0; n < 4; n++) {
					t = k * 4 + n;	// mcs0 - mcs9
					if (t < 10) {
						p->vht[i][j][k].sc[n] = calc_dbm(q->vht[i][j][k].sc[n], pwr->cal_ref_ht40[i]);
					}
				}
			}
		}
	}
}

static int wl_dump_curpower(struct rtl8192cd_priv *priv, wl_info_t *wl, struct seq_file *s)
{
	wl_txpwr_t pwr;

	memset(&pwr, 0, sizeof(pwr));
	pwr.channel = priv->pmib->dot11RFEntry.dot11channel;
	pwr.bw = (!priv->pshare->is_40m_bw) ? 20 : (priv->pshare->is_40m_bw * 40);

	if (pwr.channel < 36) {
		get_pwr_of_8192e(priv, wl, &pwr);
	} else {
		get_pwr_of_8814a(priv, wl, &pwr);
	}
	print_pwr(s, &pwr);
	return (0);
}

/*--------------------------------------------------------------------------*/
static int set_pwr_of_8192e(struct rtl8192cd_priv *priv, int path, int kind, int index, int nss, uint32 ddbm, int sign)
{
	uint32 ofdm_regs[] = { 0xe00, 0xe04, 0x830, 0x834 };
	uint32 mcs_regs[] = { 0xe10, 0xe14, 0xe18, 0xe1c, 0x83c, 0x848, 0x84c, 0x868 };
	uint32 reg;
	unsigned char ref, val;
	int channel = priv->pmib->dot11RFEntry.dot11channel;
	int diff;
	reg_v_t v;

	if (path == 0) {
		if (kind == WL_KIND_CCK)
			ref = priv->pmib->dot11RFEntry.pwrlevelCCK_A[channel - 1];
		else
			ref = priv->pmib->dot11RFEntry.pwrlevelHT40_1S_A[channel - 1];
	} else {
		if (kind == WL_KIND_CCK)
			ref = priv->pmib->dot11RFEntry.pwrlevelCCK_B[channel - 1];
		else
			ref = priv->pmib->dot11RFEntry.pwrlevelHT40_1S_B[channel - 1];
	}
	diff = (int)(ddbm - (17 * 2));
	val = ref + diff;

	switch (kind) {
	case WL_KIND_CCK:
		if (path == 0) {
			if (index == 0) {
				v.ui = read_pwr_reg(0xe08);
				if (sign < 0) {
					v.uc[1] -= ddbm;
				} else if (sign > 0) {
					v.uc[1] += ddbm;
				} else {
					v.uc[1] = val;
				}
				write_pwr_reg(0xe08, v.ui);
			} else {
				v.ui = read_pwr_reg(0x86c);
				if (sign < 0) {
					v.uc[index] -= ddbm;
				} else if (sign > 0) {
					v.uc[index] += ddbm;
				} else {
					v.uc[index] = val;
				}
				write_pwr_reg(0x86c, v.ui);
			}
			if (sign < 0) {
				priv->pshare->phw->CCKTxAgc_A[index] -= ddbm;
			} else if (sign > 0) {
				priv->pshare->phw->CCKTxAgc_A[index] += ddbm;
			} else {
				priv->pshare->phw->CCKTxAgc_A[index] = diff;
			}
		} else {
			if (index == 3) {
				v.ui = read_pwr_reg(0x86c);
				if (sign < 0) {
					v.uc[0] -= ddbm;
				} else if (sign > 0) {
					v.uc[0] += ddbm;
				} else {
					v.uc[0] = val;
				}
				write_pwr_reg(0x86c, v.ui);
			} else {
				v.ui = read_pwr_reg(0x838);
				if (sign < 0) {
					v.uc[index + 1] -= ddbm;
				} else if (sign > 0) {
					v.uc[index + 1] += ddbm;
				} else {
					v.uc[index + 1] = val;
				}
				write_pwr_reg(0x838, v.ui);
			}
			if (sign < 0) {
				priv->pshare->phw->CCKTxAgc_B[index] -= ddbm;
			} else if (sign > 0) {
				priv->pshare->phw->CCKTxAgc_B[index] += ddbm;
			} else {
				priv->pshare->phw->CCKTxAgc_B[index] = diff;
			}
		}
		break;
	case WL_KIND_OFDM:
		reg = ofdm_regs[path * 2 + ((index / 4) & 1)];
		v.ui = read_pwr_reg(reg);
		if (sign < 0) {
			v.uc[index % 4] -= ddbm;
		} else if (sign > 0) {
			v.uc[index % 4] += ddbm;
		} else {
			v.uc[index % 4] = val;
		}
		write_pwr_reg(reg, v.ui);
		if (!path) {
			if (sign < 0) {
				priv->pshare->phw->OFDMTxAgcOffset_A[index] -= ddbm;
			} else if (sign > 0) {
				priv->pshare->phw->OFDMTxAgcOffset_A[index] += ddbm;
			} else {
				priv->pshare->phw->OFDMTxAgcOffset_A[index] = diff;
			}
		} else {
			if (sign < 0) {
				priv->pshare->phw->OFDMTxAgcOffset_B[index] -= ddbm;
			} else if (sign > 0) {
				priv->pshare->phw->OFDMTxAgcOffset_B[index] += ddbm;
			} else {
				priv->pshare->phw->OFDMTxAgcOffset_B[index] = diff;
			}
		}
		break;
	case WL_KIND_MCS:
		reg = mcs_regs[path * 4 + ((index / 4) & 3)];
		v.ui = read_pwr_reg(reg);
		if (sign < 0) {
			v.uc[index % 4] -= ddbm;
		} else if (sign > 0) {
			v.uc[index % 4] += ddbm;
		} else {
			v.uc[index % 4] = val;
		}
		write_pwr_reg(reg, v.ui);
		if (!path) {
			if (sign < 0) {
				priv->pshare->phw->MCSTxAgcOffset_A[index] -= ddbm;
			} else if (sign > 0) {
				priv->pshare->phw->MCSTxAgcOffset_A[index] += ddbm;
			} else {
				priv->pshare->phw->MCSTxAgcOffset_A[index] = diff;
			}
		} else {
			if (sign < 0) {
				priv->pshare->phw->MCSTxAgcOffset_B[index] -= ddbm;
			} else if (sign > 0) {
				priv->pshare->phw->MCSTxAgcOffset_B[index] += ddbm;
			} else {
				priv->pshare->phw->MCSTxAgcOffset_B[index] = diff;
			}
		}
		break;
	case WL_KIND_VHT:
	default:
		return (-1);
		break;
	}
	return (0);
}

static int set_pwr_of_8814a(struct rtl8192cd_priv *priv, int path, int kind, int index, int nss, uint32 ddbm, int sign)
{
	unsigned char ref, val;
	int channel = priv->pmib->dot11RFEntry.dot11channel;
	int diff;

	if (path == 0) {
		ref = priv->pmib->dot11RFEntry.pwrlevel5GHT40_1S_B[channel - 1];
	} else {
		ref = priv->pmib->dot11RFEntry.pwrlevel5GHT40_1S_C[channel - 1];
	}
	diff = (int)(ddbm - (17 * 2));
	val = ref + diff;

	switch (kind) {
	case WL_KIND_OFDM:
		if (sign < 0) {
			priv->pshare->phw->CurrentTxAgcOFDM[path + 1][index] -= ddbm;
		} else if (sign > 0) {
			priv->pshare->phw->CurrentTxAgcOFDM[path + 1][index] += ddbm;
		} else {
			priv->pshare->phw->CurrentTxAgcOFDM[path + 1][index] = val;
		}
		break;
	case WL_KIND_MCS:
		if (sign < 0) {
			priv->pshare->phw->CurrentTxAgcMCS[path + 1][index] -= ddbm;
		} else if (sign > 0) {
			priv->pshare->phw->CurrentTxAgcMCS[path + 1][index] += ddbm;
		} else {
			priv->pshare->phw->CurrentTxAgcMCS[path + 1][index] = val;
		}
		break;
	case WL_KIND_VHT:
		if (sign < 0) {
			priv->pshare->phw->CurrentTxAgcVHT[path + 1][nss * 10 + index] -= ddbm;
		} else if (sign > 0) {
			priv->pshare->phw->CurrentTxAgcVHT[path + 1][nss * 10 + index] += ddbm;
		} else {
			priv->pshare->phw->CurrentTxAgcVHT[path + 1][nss * 10 + index] = val;
		}
		break;
	case WL_KIND_CCK:
	default:
		return (-1);
		break;
	}
	return (0);
}

static int modify_txpower(struct rtl8192cd_priv *priv, int path, int kind, int index, int nss, uint32 ddbm, int sign)
{
	int channel = priv->pmib->dot11RFEntry.dot11channel;
	int ret = 0;

	if (path < 0 || path > 1)
		return -1;
	if (index < 0 || index > 15)
		return -1;
	if (nss < 0 || nss > 1)
		return -1;
	if (ddbm > (30 * 2))
		return -1;

	if (channel < 36) {
		ret = set_pwr_of_8192e(priv, path, kind, index, nss, ddbm, sign);
	} else {
		ret = set_pwr_of_8814a(priv, path, kind, index, nss, ddbm, sign);
	}

	return (ret);
}

static int modify_txpower_all(struct rtl8192cd_priv *priv, int path, uint32 ddbm, int sign)
{
	int index, nss;

	for (index = 0; index < 4; index++) {
		modify_txpower(priv, path, WL_KIND_CCK, index, 0, ddbm, sign);
	}
	for (index = 0; index < 8; index++) {
		modify_txpower(priv, path, WL_KIND_OFDM, index, 0, ddbm, sign);
	}
	for (index = 0; index < 16; index++) {
		modify_txpower(priv, path, WL_KIND_MCS, index, 0, ddbm, sign);
	}
	for (nss = 0; nss < 2; nss++) {
		for (index = 0; index < 10; index++) {
			modify_txpower(priv, path, WL_KIND_VHT, index, nss, ddbm, sign);
		}
	}
	return (0);
}

static int wl_cmd_set_txpower(void *handle, cmd_tbl_t *tbl, int argc, char **argv)
{
	wl_info_t *wl = (wl_info_t *) handle;
	struct rtl8192cd_priv *priv = wl->priv;
	uint32 ddbm;
	int ret, path, kind, index = 0, nss = 0, sign = 0;
	char *rate;

	if (argc < 4)
		return (-1);

	path = (int)simple_strtoul(argv[1], NULL, 10);
	ddbm = str2ddbm(argv[3], &sign);

	if (!(path < 2 && ddbm > 0 && ddbm < (30 * 2)))
		return (-1);

	if (!strncmp(argv[2], "all", 3)) {
		ret = modify_txpower_all(priv, path, ddbm, sign);
		return (ret);
	} else if (!strncmp(argv[2], "cck", 3)) {
		kind = WL_KIND_CCK;
		rate = argv[2] + 3;
	} else if (!strncmp(argv[2], "ofdm", 4)) {
		kind = WL_KIND_OFDM;
		rate = argv[2] + 4;
	} else if (!strncmp(argv[2], "mcs", 3)) {
		kind = WL_KIND_MCS;
		rate = argv[2] + 3;
	} else if (!strncmp(argv[2], "vht", 3)) {
		kind = WL_KIND_VHT;
		rate = argv[2] + 3;
		nss = simple_strtoul(argv[2] + 3, &rate, 10) - 1;
		if (rate++ == NULL)
			return (-1);
	} else {
		return (-1);
	}
	if (rate != NULL)
		index = simple_strtoul(rate, NULL, 10);

	ret = modify_txpower(priv, path, kind, index, nss, ddbm, sign);
	return (ret);
}

/*--------------------------------------------------------------------------*/
static int wl_cmd_send_test_frame(void *handle, cmd_tbl_t *tbl, int argc, char **argv)
{
	wl_info_t *wl = (wl_info_t *) handle;
	struct rtl8192cd_priv *priv = wl->priv;
	struct wifi_mib *pmib;
	unsigned char *pbuf;
	DECLARE_TXINSN(txinsn);

	pmib = GET_MIB(priv);
	txinsn.retry = 1;
	txinsn.q_num = wl->test_frame.qnum;
	txinsn.fr_type = _PRE_ALLOCMEM_;
	txinsn.tx_rate = wl->test_frame.rate;
	txinsn.fixed_rate = 1;

	txinsn.phdr = get_wlanhdr_from_poll(priv);

	// to print out statistics
	wl->op_mode = tbl->oper_mode;

	if (txinsn.phdr == NULL) {
		wl->test_frame.tx_fail_cnt += 1;
//        printk("%s:%d txinsn.phdr NULL\n", __FUNCTION__, __LINE__);
		goto send_fail;
	}

	pbuf = txinsn.pframe = get_mgtbuf_from_poll(priv);
	if (txinsn.pframe == NULL) {
		wl->test_frame.tx_fail_cnt += 1;
//        printk("%s:%d txinsn.pframe NULL\n", __FUNCTION__, __LINE__);
		goto send_fail;
	}

	memset((void *)(txinsn.phdr), 0, sizeof(struct wlan_hdr));

	SetFrameSubType(txinsn.phdr, wl->test_frame.subtype);

	if (!memcmp(wl->test_frame.sa, "\x00\x00\x00\x00\x00\x00", MACADDRLEN)) {
		memcpy(wl->test_frame.sa, GET_MY_HWADDR, MACADDRLEN);
		memcpy(wl->test_frame.bssid, GET_MY_HWADDR, MACADDRLEN);
	}
	memcpy((void *)GetAddr1Ptr((txinsn.phdr)), wl->test_frame.da, MACADDRLEN);
	memcpy((void *)GetAddr2Ptr((txinsn.phdr)), wl->test_frame.sa, MACADDRLEN);
	memcpy((void *)GetAddr3Ptr((txinsn.phdr)), wl->test_frame.bssid, MACADDRLEN);

	txinsn.hdr_len = 0;	// hdr_len add in check_desc
	txinsn.fr_len = wl->test_frame.len;
	pbuf[0] = 127;		// vendor specific action category
	pbuf[1] = 0x00;		// davolink OUI
	pbuf[2] = 0x08;
	pbuf[3] = 0x52;
	memset(&pbuf[4], 0, wl->test_frame.len - 4);

	if ((rtl8192cd_firetx(priv, &txinsn)) == SUCCESS) {
		wl->test_frame.tx_succ_cnt += 1;
		return 0;
	} else {
		wl->test_frame.tx_fail_cnt += 1;
//        printk("%s:%d tx_fail\n", __FUNCTION__, __LINE__);
	}

 send_fail:

	if (txinsn.phdr)
		release_wlanhdr_to_poll(priv, txinsn.phdr);
	if (txinsn.pframe)
		release_mgtbuf_to_poll(priv, txinsn.pframe);
	return -1;
}

/*--------------------------------------------------------------------------*/
extern const u2Byte VHT_MCS_DATA_RATE[3][2][30];
static int conv_rate_to_mbps(unsigned int rate, int bw, int sg)
{
	int mbps = rate;
	if (is_MCS_rate(rate)) {
#ifdef RTK_AC_SUPPORT
		if (is_VHT_rate(rate)) {
			mbps = VHT_MCS_DATA_RATE[MIN_NUM(bw, 2)][sg][(rate - VHT_RATE_ID)];
		} else
#endif
		{
			char index = rate & 0xf;
			mbps = VHT_MCS_DATA_RATE[MIN_NUM(bw, 1)][sg][(index < 8) ? index : (index + 2)];
		}
	}
	return (mbps >> 1);
}

static char *rate_to_str(char *buf, int bufsz, unsigned int rate, int bw, int sg)
{
	int mbps = conv_rate_to_mbps(rate, bw, sg);
#ifdef RTK_AC_SUPPORT		//vht rate , todo, dump vht rates in Mbps
	if (rate >= VHT_RATE_ID) {
		snprintf(buf, bufsz, "vht%d-%d(%dMbps)", ((rate - VHT_RATE_ID) / 10) + 1, (rate - VHT_RATE_ID) % 10, mbps);
	} else
#endif
	if (is_MCS_rate(rate)) {
		snprintf(buf, bufsz, "mcs%d(%dMbps)", (rate - HT_RATE_ID), mbps);
	} else {
		snprintf(buf, bufsz, "%dMbps", rate / 2);
	}
	return (buf);
}

static char *str_chipvendor(struct stat_info *pstat, char *buf, int bufsz)
{
	if (pstat->is_realtek_sta)
		snprintf(buf, bufsz, "Realtek");
	else if (pstat->IOTPeer == HT_IOT_PEER_BROADCOM)
		snprintf(buf, bufsz, "Broadcom");
	else if (pstat->IOTPeer == HT_IOT_PEER_MARVELL)
		snprintf(buf, bufsz, "Marvell");
	else if (pstat->IOTPeer == HT_IOT_PEER_INTEL)
		snprintf(buf, bufsz, "Intel");
	else if (pstat->IOTPeer == HT_IOT_PEER_RALINK)
		snprintf(buf, bufsz, "Ralink");
	else if (pstat->IOTPeer == HT_IOT_PEER_HTC)
		snprintf(buf, bufsz, "HTC");
	else
		snprintf(buf, bufsz, "--");

	return (buf);
}

static int wl_dump_one_sta(struct rtl8192cd_priv *priv, struct stat_info *pstat, struct seq_file *s, int num, int bssnum)
{
	char txr[40], rxr[40], buf[40];
	unsigned int rssi[2];

	rate_to_str(txr, sizeof(txr), pstat->current_tx_rate, pstat->tx_bw,
		    (pstat->ht_current_tx_info & TX_USE_SHORT_GI) ? 1 : 0);
	rate_to_str(rxr, sizeof(rxr), pstat->rx_rate, pstat->rx_bw, (pstat->rx_splcp & 0x01) ? 1 : 0);
	if (priv->pmib->dot11RFEntry.phyBandSelect == PHY_BAND_5G) {
		rssi[0] = pstat->rf_info.mimorssi[1];
		rssi[1] = pstat->rf_info.mimorssi[2];
	} else {
		rssi[0] = pstat->rf_info.mimorssi[0];
		rssi[1] = pstat->rf_info.mimorssi[1];
	}

	seq_printf(s, "[%02d] %pM BSS=%d (rx=%s tx=%s)\n", num, pstat->hwaddr, bssnum, rxr, txr);

	seq_printf(s, "\trssi=%u(%u,%u) bw=%d,%dMHz ratr_idx=0x%x\n",
		   pstat->rssi, rssi[0], rssi[1],
		   (pstat->tx_bw ? (pstat->tx_bw * 40) : 20), (0x1 << (pstat->rx_bw)) * 20, pstat->ratr_idx);

	seq_printf(s, "\tin=%lu v=%s sleep=%s support_mcs=%x state=%x\n",
		   pstat->link_time,
		   str_chipvendor(pstat, buf, sizeof(buf)),
		   (!list_empty(&pstat->sleep_list)) ? "yes" : "no",
		   cpu_to_le32(pstat->vht_cap_buf.vht_support_mcs[0]), pstat->state);

	seq_printf(s, "\taid=%d dzq=%d tx=%u txfail=%u rx=%u txb%u:%u rxb%u:%u \n", pstat->aid,
		   skb_queue_len(&pstat->dz_queue),
		   pstat->tx_only_data_packets, pstat->tx_fail,
		   pstat->rx_only_data_packets,
		   pstat->tx_only_data_bytes_high, pstat->tx_only_data_bytes,
		   pstat->rx_only_data_bytes_high, pstat->rx_only_data_bytes);

	return (0);
}

static int wl_dump_sta(wl_info_t *wl, struct seq_file *s)
{
	struct rtl8192cd_priv *priv = wl->priv;
	int i, j, sta_num = 0;
	struct list_head *phead, *plist;
	struct stat_info *pstat;

	phead = &GET_ROOT(priv)->asoc_list;
	plist = phead->next;
	for (j = 0; j < GET_ROOT(priv)->assoc_num && plist != phead; j++) {
		pstat = list_entry(plist, struct stat_info, asoc_list);
		wl_dump_one_sta(GET_ROOT(priv), pstat, s, sta_num++, 0);
		plist = plist->next;
	}
#if defined(MBSSID)
	for (i = 0; i < RTL8192CD_NUM_VWLAN; i++) {
		if (IS_DRV_OPEN(GET_ROOT(priv)->pvap_priv[i])) {
			phead = &(GET_ROOT(priv)->pvap_priv[i])->asoc_list;
			plist = phead->next;
			for (j = 0; j < (GET_ROOT(priv)->pvap_priv[i])->assoc_num && plist != phead; j++) {
				pstat = list_entry(plist, struct stat_info, asoc_list);
				wl_dump_one_sta(GET_ROOT(priv)->pvap_priv[i], pstat, s, sta_num++, i + 1);
				plist = plist->next;
			}
		}
	}
#endif
	if (sta_num > 0)
		seq_printf(s, "\n");
	return (0);
}

/*--------------------------------------------------------------------------*/
static int wl_dump_one_bss(struct rtl8192cd_priv *priv, int bssnum, struct seq_file *s)
{
	struct dv_priv_t *dv_priv = (struct dv_priv_t *)priv->dv_priv;
	char buf[40];

	seq_printf(s, "\nBSS%d\t%pM ", bssnum, priv->pmib->dot11StationConfigEntry.dot11Bssid);
	memcpy(buf, priv->pmib->dot11StationConfigEntry.dot11DesiredSSID,
	       priv->pmib->dot11StationConfigEntry.dot11DesiredSSIDLen);
	buf[priv->pmib->dot11StationConfigEntry.dot11DesiredSSIDLen] = '\0';
	seq_printf(s, "SSID=\"%s\" bi=%d dtim=%d\n", buf,
		   priv->pmib->dot11StationConfigEntry.dot11BeaconPeriod, priv->pmib->dot11StationConfigEntry.dot11DTIMPeriod);

	seq_printf(s, "\tup %lu tx=%lu fail=%lu drop=%lu rx=%lu decache=%lu reuse=%lu\n",
		   priv->up_time,
		   priv->net_stats.tx_packets,
		   priv->net_stats.tx_errors,
		   priv->ext_stats.tx_drops, priv->net_stats.rx_packets, priv->ext_stats.rx_decache, priv->ext_stats.rx_reuse);

	seq_printf(s, "\tbeacon ok=%lu err=%lu hangup-check tx=%d rx=%d bcn=%d rst=%d\n",
		   priv->ext_stats.beacon_ok, priv->ext_stats.beacon_er,
#ifdef CHECK_TX_HANGUP
		   priv->check_cnt_tx,
#else
		   -1,
#endif
#if defined(CHECK_RX_HANGUP) || defined(CHECK_RX_DMA_ERROR)
		   priv->check_cnt_rx,
#else
		   -1,
#endif
#ifdef CHECK_BEACON_HANGUP
		   priv->check_cnt_bcn,
#else
		   -1,
#endif
#ifdef CHECK_AFTER_RESET
		   priv->check_cnt_rst
#else
		   -1
#endif
	    );

#ifdef DV_RXDESC_CHECK_WATCHDOG	/* APACRTL-182, WR for no rx auth from sta */
	if (dv_priv != NULL && bssnum == 0) {
		seq_printf(s, "\trxbd_check rx_isr_done=%u recover=%u\n",
			   dv_priv->rxbd_check.rx_count, dv_priv->rxbd_check.recover_cnt);
	}
#endif

	return (0);
}

static int wl_dump_bss(wl_info_t *wl, struct seq_file *s)
{
	struct rtl8192cd_priv *priv = wl->priv;
	char buf[40];
	int i;

	seq_printf(s, "channel = %s\n", get_current_channel_str(priv, buf, sizeof(buf)));
	seq_printf(s, "FA=%d CCA=%d\n", ODMPTR->FalseAlmCnt.Cnt_all, ODMPTR->FalseAlmCnt.Cnt_CCA_all);

	wl_dump_one_bss(GET_ROOT(priv), 0, s);
#if defined(MBSSID)
	for (i = 0; i < RTL8192CD_NUM_VWLAN; i++) {
		if (IS_DRV_OPEN(GET_ROOT(priv)->pvap_priv[i])) {
			wl_dump_one_bss(GET_ROOT(priv)->pvap_priv[i], i + 1, s);
		}
	}
#endif
	seq_printf(s, "\n");
	return (0);
}

/*--------------------------------------------------------------------------*/
/* APACRTL-213, for rx frame statistics */
static int wl_dump_rxpkt_stats(wl_info_t *wl, struct seq_file *s)
{
	struct rtl8192cd_priv *priv = wl->priv;
	struct dv_priv_t *dv_priv = (struct dv_priv_t *)priv->dv_priv;

	seq_printf(s, "Rx packet statistics (ROOT priv only)\n");
	seq_printf(s, "valid count = %u, %u, %u\n", dv_priv->rxcnt.valid[0], dv_priv->rxcnt.valid[1], dv_priv->rxcnt.valid[2]);
	seq_printf(s, "ibss=%u obss=%u crcerr=%u mgnt=%u ctrl=%u data=%u\n",
		   dv_priv->rxcnt.ibss, dv_priv->rxcnt.obss, dv_priv->rxcnt.crcerr,
		   dv_priv->rxcnt.mgnt, dv_priv->rxcnt.ctrl, dv_priv->rxcnt.data);
	seq_printf(s, "prbreq=%u auth=%u deauth=%u assoc=%u beacon=%u\n",
		   dv_priv->rxcnt.prbreq, dv_priv->rxcnt.auth, dv_priv->rxcnt.deauth,
		   dv_priv->rxcnt.assoc, dv_priv->rxcnt.beacon);
	seq_printf(s, "\n");
	return (0);
}

/*--------------------------------------------------------------------------*/
static int wl_dump_log(wl_info_t *wl, struct seq_file *s, int count)
{
	int i, j, len = 0;
	unsigned int ts, now;

	now = os_msec();
	j = (wl->log.index + WL_LOG_SIZE - 1) % WL_LOG_SIZE;
	for (i = 0; i < WL_LOG_SIZE; i++) {
		if (wl->log.buf[j][0] != '\0') {
			ts = now - wl->log.ts[j];
			len += seq_printf(s, "%3d.%02d %s\n", ts / 1000, (ts % 1000) / 10, wl->log.buf[j]);
		}
		j = (j + WL_LOG_SIZE - 1) % WL_LOG_SIZE;
		if (count > 0) {
			if (--count <= 0)
				break;
		}
	}
	if (len > 0)
		seq_printf(s, "\n\n");
	return (0);
}

/*--------------------------------------------------------------------------*/
static int wl_dump_walk_dbg(wl_info_t *wl, struct seq_file *s)
{
#ifdef DV_WLCMD_DEBUG_COUNT
	int i, len;

	for (i = 0; i < WL_WALK_DBG_BUF_SIZE; i++) {
		if (!wl->walk_dbg[i].lineno)
			break;
		len += seq_printf(s, "%2d %s:%d %d\n", i, wl->walk_dbg[i].pos, wl->walk_dbg[i].lineno, wl->walk_dbg[i].refcnt);
	}
	if (len > 0)
		seq_printf(s, "\n");
#endif
	return (0);
}

/*--------------------------------------------------------------------------*/
static int wl_dump_default(wl_info_t *wl, struct seq_file *s)
{
	switch (wl->dump_mode) {
	case WL_DUMP_LIST:
		seq_printf(s, "list\nsta\nbss\nlog\nwalk\nrxpkt\n\n");
		break;

	case WL_DUMP_STA:
		wl_dump_sta(wl, s);
		break;

	case WL_DUMP_BSS:
		wl_dump_bss(wl, s);
		break;

	case WL_DUMP_LOG:
		wl_dump_log(wl, s, 0);
		break;

	case WL_DUMP_WALK_DBG:
		wl_dump_walk_dbg(wl, s);
		break;

	case WL_DUMP_RXPKT_STATS:
		wl_dump_rxpkt_stats(wl, s);
		break;

	default:
		wl_dump_bss(wl, s);
		wl_dump_log(wl, s, 20);
		wl_dump_sta(wl, s);
		break;
	}
	return (0);
}

/*--------------------------------------------------------------------------*/
/*--------------------------------------------------------------------------*/
/*--------------------------------------------------------------------------*/
/*--------------------------------------------------------------------------*/
/*--------------------------------------------------------------------------*/
/*--------------------------------------------------------------------------*/
/*--------------------------------------------------------------------------*/
/*--------------------------------------------------------------------------*/
/*--------------------------------------------------------------------------*/
/*--------------------------------------------------------------------------*/
/*--------------------------------------------------------------------------*/
/*--------------------------------------------------------------------------*/
/*--------------------------------------------------------------------------*/
/*--------------------------------------------------------------------------*/
/*--------------------------------------------------------------------------*/
/*--------------------------------------------------------------------------*/
/*
 * Global Functions
 */
/*--------------------------------------------------------------------------*/
#ifdef DV_WLCMD_DEBUG_COUNT
void dv_wl_inc_debug_count(struct rtl8192cd_priv *priv, char *pos, int lineno)
{
	wl_info_t *wl = get_wl_from_priv(priv);
	int i;

	for (i = 0; i < WL_WALK_DBG_BUF_SIZE; i++) {
		if (!wl->walk_dbg[i].lineno)
			break;
		if (wl->walk_dbg[i].lineno == lineno && !strncmp(wl->walk_dbg[i].pos, pos, sizeof(wl->walk_dbg[i].pos) - 1)) {
			wl->walk_dbg[i].refcnt++;
			return;
		}
	}

	if (i < WL_WALK_DBG_BUF_SIZE) {
		wl->walk_dbg[i].lineno = lineno;
		strncpy(wl->walk_dbg[i].pos, pos, sizeof(wl->walk_dbg[i].pos) - 1);
		wl->walk_dbg[i].refcnt++;
	}
}
#endif

/*--------------------------------------------------------------------------*/
int dv_wl_tx_retry_limit(struct rtl8192cd_priv *priv)
{
	wl_info_t *wl = get_wl_from_priv(priv);
	return (wl->tx_retry_limit);
}

/*--------------------------------------------------------------------------*/
int dv_wl_force_tx_rate(struct rtl8192cd_priv *priv)
{
	wl_info_t *wl = get_wl_from_priv(priv);
	return (wl->force_tx_rate ? 1 : 0);
}

unsigned int dv_wl_get_tx_rate(struct rtl8192cd_priv *priv, unsigned int current_tx_rate)
{
	unsigned int new_tx_rate;
	wl_info_t *wl = get_wl_from_priv(priv);

	if (!wl->force_tx_rate)
		return (current_tx_rate);

	if (wl->force_tx_rate & WLCMD_TX_RATE_PLUS) {
		if (!is_MCS_rate((unsigned char)current_tx_rate))
			return (current_tx_rate);
		new_tx_rate = current_tx_rate + (wl->force_tx_rate & 7);
		if (current_tx_rate < _MCS8_RATE_) {
			if (new_tx_rate > _MCS7_RATE_)
				new_tx_rate = _MCS7_RATE_;
		} else if (current_tx_rate < _MCS16_RATE_) {
			if (new_tx_rate > _MCS15_RATE_)
				new_tx_rate = _MCS15_RATE_;
		} else if (current_tx_rate < _MCS24_RATE_) {
			if (new_tx_rate > _MCS23_RATE_)
				new_tx_rate = _MCS23_RATE_;
		} else if (current_tx_rate < _NSS2_MCS0_RATE_) {
			if (new_tx_rate > _NSS1_MCS9_RATE_)
				new_tx_rate = _NSS1_MCS9_RATE_;
		} else if (current_tx_rate < _NSS3_MCS0_RATE_) {
			if (new_tx_rate > _NSS2_MCS9_RATE_)
				new_tx_rate = _NSS2_MCS9_RATE_;
		} else if (current_tx_rate < _NSS4_MCS0_RATE_) {
			if (new_tx_rate > _NSS3_MCS9_RATE_)
				new_tx_rate = _NSS3_MCS9_RATE_;
		}
	} else if (wl->force_tx_rate & WLCMD_TX_RATE_MINUS) {
		if (!is_MCS_rate((unsigned char)current_tx_rate))
			return (current_tx_rate);
		new_tx_rate = current_tx_rate - (wl->force_tx_rate & 7);
		if (current_tx_rate < _MCS8_RATE_) {
			if (new_tx_rate < _MCS0_RATE_)
				new_tx_rate = _MCS0_RATE_;
		} else if (current_tx_rate < _MCS16_RATE_) {
			if (new_tx_rate < _MCS8_RATE_)
				new_tx_rate = _MCS8_RATE_;
		} else if (current_tx_rate < _MCS24_RATE_) {
			if (new_tx_rate < _MCS16_RATE_)
				new_tx_rate = _MCS16_RATE_;
		} else if (current_tx_rate < _NSS2_MCS0_RATE_) {
			if (new_tx_rate < _NSS1_MCS0_RATE_)
				new_tx_rate = _NSS1_MCS0_RATE_;
		} else if (current_tx_rate < _NSS3_MCS0_RATE_) {
			if (new_tx_rate < _NSS2_MCS0_RATE_)
				new_tx_rate = _NSS2_MCS0_RATE_;
		} else if (current_tx_rate < _NSS4_MCS0_RATE_) {
			if (new_tx_rate < _NSS3_MCS0_RATE_)
				new_tx_rate = _NSS3_MCS0_RATE_;
		}
	} else {
		new_tx_rate = wl->force_tx_rate & 0x0ff;
	}
	wl->tx_rate_cnt++;
	return (new_tx_rate);
}

/*--------------------------------------------------------------------------*/
int dv_wl_log_update(struct rtl8192cd_priv *priv, int which, char *log)
{
	wl_info_t *wl = get_wl_from_priv(priv);
	int aid = 0, log_to_console = 1;	// default: log to console

	if (wl != NULL && (wl->log.flag & which)) {
		if (!(wl->log.flag & WL_LOG_FLAG_TO_CONSOLE))
			log_to_console = 0;

		if (wl->log.aid != 0)
			aid = (log[0] == '[') ? simple_strtoul(&log[1], NULL, 10) : 0;
		if (wl->log.aid == aid) {
			snprintf(wl->log.buf[wl->log.index], WL_LOG_MAX_LEN - 1, "%s", log);
			wl->log.ts[wl->log.index] = os_msec();
			wl->log.index = (wl->log.index + 1) % WL_LOG_SIZE;
		}
	}
	return (log_to_console);
}

int dv_wl_log_enable(struct rtl8192cd_priv *priv, int which, unsigned int macid)
{
	wl_info_t *wl = get_wl_from_priv(priv);

	if (wl != NULL && (wl->log.flag & which)) {
		if (!wl->log.aid || macid == (unsigned int)wl->log.aid)
			return (1);
	}
	return (0);
}

/*--------------------------------------------------------------------------*/
static wl_info_t *wl_init_variables(struct rtl8192cd_priv *priv)
{
	wl_info_t *wl = get_wl_from_priv(priv);

	wl->priv = priv;
	memcpy(wl->test_frame.sa, GET_MY_HWADDR, MACADDRLEN);
	memcpy(wl->test_frame.da, "\x00\x11\x22\x33\x44\x55", MACADDRLEN);
	memcpy(wl->test_frame.bssid, GET_MY_HWADDR, MACADDRLEN);
	wl->test_frame.subtype = WIFI_WMM_ACTION;
	wl->test_frame.qnum = BE_QUEUE;
	wl->test_frame.rate = 12;	/* 6Mbps */
	wl->test_frame.len = 100;

	return (wl);
}

void dv_wl_cmd_init(struct rtl8192cd_priv *priv, struct proc_dir_entry *wlan_proc)
{
	wl_info_t *wl;

	if (!IS_ROOT_INTERFACE(priv))
		return;

	wl = wl_init_variables(priv);

	if (wl != NULL)
		proc_create_data("wl_cmd", 0644, wlan_proc, &wl_cmd_fops, (void *)wl);
}

void dv_wl_cmd_deinit(struct rtl8192cd_priv *priv, struct proc_dir_entry *wlan_proc)
{
	if (!IS_ROOT_INTERFACE(priv))
		return;

	remove_proc_entry("wl_cmd", wlan_proc);
}
