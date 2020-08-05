#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/spinlock.h>
#include <linux/sysctl.h>
#include <linux/delay.h>
#include <linux/ctype.h>
#include "brdio.h"

#include <net/rtl/rtl_types.h>
#include <net/rtl/rtl_glue.h>
#include <net/rtl/rtl865x_netif.h>
#include "common/rtl865x_netif_local.h"
#include "common/rtl865x_eventMgr.h"
#include "common/rtl_utils.h"
#include "AsicDriver/asicRegs.h"
#include "AsicDriver/rtl865x_asicBasic.h"
#include "AsicDriver/rtl865x_asicCom.h"
#include "AsicDriver/rtl865x_asicL2.h"
#include <linux/sort.h>

extern int32 rtl865xC_setAsicEthernetForceModeRegs(uint32 port, uint32 enForceMode, uint32 forceLink, uint32 forceSpeed, uint32 forceDuplex);
extern int32 rtl8651_setAsicEthernetPHYSpeed(uint32 port, uint32 speed);
extern int32 rtl8651_setAsicEthernetPHYAdvCapality(uint32 port, uint32 capality);
extern int32 rtl8651_setAsicEthernetPHYAutoNeg(uint32 port, uint32 autoneg);
extern int32 rtl8651_setAsicEthernetPHYDuplex(uint32 port, uint32 duplex);
extern int32 rtl8651_setAsicEthernetPHYPowerDown(uint32, uint32);
#if defined(CONFIG_RTL_8197F) && defined(CONFIG_RTL_8211F_SUPPORT)
extern int gpio_simulate_mdc_mdio;
#endif

struct gpio_pin_mux {
	unsigned char alpha;			/* 0 ~ 255 */

	unsigned char digit:3;			/* 0 ~ 7 */
	unsigned char offset:5;			/* 0 ~ 31 */

	unsigned char pinno:7;			/* 0 ~ 127 */
	unsigned char active_low:1;		/* 0 ~ 1 */

	unsigned char mask_len:3;		/* 0 ~ 7 */
	unsigned char value:5;			/* 0 ~ 31 */
};

static struct gpio_pin_mux board_gpm_map[] = {
	#include "rtl8197f_gpio_pinmux_map.c"
};

static int board_gpm_sorted = 0;

static int
cmpr(const struct gpio_pin_mux *lhs, const struct gpio_pin_mux *rhs)
{
	char b1[16], b2[16];
	snprintf(b1, sizeof(b1), "%c%u", lhs->alpha, lhs->digit);
	snprintf(b2, sizeof(b2), "%c%u", rhs->alpha, rhs->digit);
	return strncasecmp(b1, b2, 2);
}

static const struct gpio_pin_mux *gpio_name_match(const char *name)
{
	int i, mid, left = 0;
	int right = ARRAY_SIZE(board_gpm_map) - 1;

	if (unlikely(board_gpm_sorted == 0)) {
		sort(board_gpm_map, ARRAY_SIZE(board_gpm_map),
		     sizeof(board_gpm_map[0]), (void *)cmpr, NULL);
		board_gpm_sorted = 1;
	}

	while (right >= left) {
		mid = (right + left) >> 1;
		if ((i = toupper(name[0]) - board_gpm_map[mid].alpha) == 0) {
			if ((i = (name[1] - '0') - board_gpm_map[mid].digit) == 0)
				i = name[2] - '\0';
		}
		if (i == 0)
			return &board_gpm_map[mid];
		if (i < 0)
			right = mid - 1;
		else
			left = mid + 1;
	}
	return NULL;
}

static int brdio_phreq(unsigned int cmd, struct phreq __user * arg)
{
	struct phreq phr;
	uint32 regs, rvalue, pcr, bmcr;
	uint8 rxpause, txpause;
	int forceMode = 1;	/* Force */
	int forceSpeed = 2;	/* 1G */
	int forceDuplex = 1;	/* Full */
	uint32 acap = 0;	/* advertising capability */
	int phyid;

	if (copy_from_user((char *)&phr, arg, sizeof(phr)))
		return -EFAULT;

	if (phr.phr_port < PH_MINPORT || phr.phr_port > PH_MAXPORT)
		return -EINVAL;

	switch (cmd) {
	case __PHGIO:
		phr.phr_optmask = 0;
#if defined(CONFIG_RTL_8197F) && defined(CONFIG_RTL_8211F_SUPPORT)
		if (gpio_simulate_mdc_mdio && ((phyid = rtl8651AsicEthernetTable[phr.phr_port].phyId) > 4)) {
			rtl_mdio_write(phyid, 31, 0xa43);
			rtl_mdio_read(phyid, 0x1a, &regs);
			rtl_mdio_write(phyid, 31, 0);
			if (regs & (1 << 2))
				phr.phr_optmask |= PHF_LINKUP;
			if (regs & (1 << 7))
				phr.phr_optmask |= PHF_RXPAUSE;

			if (regs & (1 << 6))
				phr.phr_optmask |= PHF_TXPAUSE;

			if (regs & (1 << 12))
				phr.phr_optmask |= PHF_AUTONEG;

			switch ((regs & (3 << 4)) >> 4) {
			case 0:
				phr.phr_optmask |= PHF_10M;
				break;
			case 1:
				phr.phr_optmask |= PHF_100M;
				break;
			case 2:
				phr.phr_optmask |= PHF_1000M;
				break;
			default:
				phr.phr_optmask |= PHF_500M;
				break;
			}
			if (regs & (1 << 3))
				phr.phr_optmask |= PHF_FDX;
			if (regs & (1 << 8))
				phr.phr_optmask |= PHF_EEE;
			return copy_to_user(arg, &phr, sizeof(phr)) ? -EFAULT : 0;
		}
#endif
		regs = READ_MEM32(PSRP0 + ((phr.phr_port) << 2));
		pcr = READ_MEM32(PCRP0 + ((phr.phr_port) << 2));
		if (pcr & EnForceMode) {
			if (pcr & PollLinkStatus)
				phr.phr_optmask |= PHF_ENFORCE_POLL;
			else
				phr.phr_optmask |= PHF_ENFORCE_NO_AUTONEG;
		}
		/* why read once again? */
		regs = READ_MEM32(PSRP0 + ((phr.phr_port) << 2));
		if (regs & PortStatusLinkUp) {
			phr.phr_optmask |= PHF_LINKUP;
			if (regs & PortStatusRXPAUSE)
				phr.phr_optmask |= PHF_RXPAUSE;

			if (regs & PortStatusTXPAUSE)
				phr.phr_optmask |= PHF_TXPAUSE;

			if (regs & PortStatusNWayEnable)
				phr.phr_optmask |= PHF_AUTONEG;

			switch ((regs & PortStatusLinkSpeed_MASK) >> PortStatusLinkSpeed_OFFSET) {
			case PortStatusLinkSpeed10M:
				phr.phr_optmask |= PHF_10M;
				break;
			case PortStatusLinkSpeed100M:
				phr.phr_optmask |= PHF_100M;
				break;
			case PortStatusLinkSpeed1000M:
				phr.phr_optmask |= PHF_1000M;
				break;
			default:
				phr.phr_optmask |= PHF_500M;
				break;
			}
			if (regs & PortStatusDuplex)
				phr.phr_optmask |= PHF_FDX;
#ifdef CONFIG_RTL_8198C
			phyid = rtl8651AsicEthernetTable[phr.phr_port].phyId;
			rtl8651_setAsicEthernetPHYReg(phyid, 31, 0xa43);
			rtl8651_getAsicEthernetPHYReg(phyid, 26, &regs);
			rtl8651_setAsicEthernetPHYReg(phyid, 31, 0);
			if (regs & 0x100)
				phr.phr_optmask |= PHF_EEE;
#endif
		}
		if (copy_to_user(arg, &phr, sizeof(phr)))
			return -EFAULT;
		return 0;

	case __PHSIO:
		phyid = rtl8651AsicEthernetTable[phr.phr_port].phyId;
#if defined(CONFIG_RTL_8197F) && defined(CONFIG_RTL_8211F_SUPPORT)
		if (gpio_simulate_mdc_mdio && phyid > 4)
			rtl_mdio_read(phyid, 0, &regs);
		else
#endif
		rtl8651_getAsicEthernetPHYReg(phyid, 0, &regs);
		/* save basic mode control register value */
		bmcr = regs;
		if (phr.phr_optmask & PHF_PWRUP) {
			if ((phr.phr_option & PHF_PWRUP))
				regs &= ~POWER_DOWN;
			else
				regs |= POWER_DOWN;
		}

		if (phr.phr_optmask & PHF_RESET)
			if ((phr.phr_option & PHF_RESET))
				regs |= PHY_RESET;

		if (!(regs & POWER_DOWN)) {
			if (phr.phr_optmask & (PHF_RXPAUSE | PHF_TXPAUSE)) {
				uint32 nvalue = 0, reg4;
#if defined(CONFIG_RTL_8197F) && defined(CONFIG_RTL_8211F_SUPPORT)
				if (gpio_simulate_mdc_mdio && phyid > 4)
					rtl_mdio_read(phyid, 4, &reg4);
				else
#endif
				rtl8651_getAsicEthernetPHYReg(phyid, 4, &reg4);
				rvalue = (reg4 >> 10) & 3;

				if (phr.phr_optmask & PHF_RXPAUSE)
					rxpause = !!(phr.phr_option & PHF_RXPAUSE);
				if (phr.phr_optmask & PHF_TXPAUSE)
					txpause = !!(phr.phr_option & PHF_TXPAUSE);

				if (txpause != rxpause)
					nvalue |= (1 << 1);
				if (rxpause)
					nvalue |= (1 << 0);
				if (nvalue != rvalue) {
					reg4 &= ~(3 << 10);
#if defined(CONFIG_RTL_8197F) && defined(CONFIG_RTL_8211F_SUPPORT)
					if (gpio_simulate_mdc_mdio && phyid > 4)
						rtl_mdio_write(phyid, 4, reg4 | (nvalue << 10));
					else
#endif
					rtl8651_setAsicEthernetPHYReg(phyid, 4, reg4 | (nvalue << 10));
					/*
					 * Whatever pause bits for ANAR are assigned, PCRP overwrites with its own bits.
					 * In other words, pause bits on PCRP have been reflected on ANAR directly.
					 * In fact rxEn means ANAR(Auto Negotiation Advertising Register)'s asym pause and
					 * txEn means actually ANAR's pause.
					 */
					rtl865xC_setAsicPortPauseFlowControl(phr.phr_port, nvalue & 2, nvalue & 1);
				}
			}

			if ((phr.phr_optmask & PHF_AUTONEG) && (phr.phr_option & PHF_AUTONEG)) {
				forceMode = forceSpeed = forceDuplex = 0;
				acap = 1 << PORT_AUTO;
			} else {
				if (phr.phr_optmask & PHF_SPEEDMASK) {
					if (phr.phr_option & PHF_10M)
						forceSpeed = 0;
					else if (phr.phr_option & PHF_100M)
						forceSpeed = 1;
					else
						forceSpeed = 2;
				}
				acap = (1 << (forceSpeed + 1));
				if (phr.phr_optmask & PHF_FDX) {
					if (!(phr.phr_option & PHF_FDX))
						forceDuplex = 0;
				}
				if (forceDuplex)
					acap <<= 3;
#ifdef CONFIG_RTL_8198C
				/* forced 1G irrespective of whichever duplex is */
				if (forceSpeed == 2) {
					forceMode = 0;
					acap = 1 << DUPLEX_1000M;
				}
#endif
			}
			if (bmcr == 0 || (bmcr & POWER_DOWN)) {
				rtl8651_setAsicEthernetPHYPowerDown(phr.phr_port, FALSE);
				mdelay(10);
			}
			rtl8651_setAsicEthernetPHYSpeed(phr.phr_port, forceSpeed);
			rtl8651_setAsicEthernetPHYDuplex(phr.phr_port, forceDuplex);
			rtl8651_setAsicEthernetPHYAutoNeg(phr.phr_port, forceMode ? FALSE : TRUE);
			rtl8651_setAsicEthernetPHYAdvCapality(phr.phr_port, acap);
			rtl865xC_setAsicEthernetForceModeRegs(phr.phr_port, forceMode, 1, forceSpeed, forceDuplex);
			rtl8651_restartAsicEthernetPHYNway(phr.phr_port);
			mdelay(10);
		} else
			rtl8651_setAsicEthernetPHYPowerDown(phr.phr_port, TRUE);
		return 0;

	default:
		break;
	}
	return -EINVAL;
}

static void reg32_modify(u32 addr, u32 data, u32 mask)
{
	u32 v32 = REG32(addr);
	v32 &= ~mask;
	v32 |= (data & mask);
	REG32(addr) = v32;
}

static inline void reg32_clear_bit(u32 addr, int nr)
{
	reg32_modify(addr, 0, 1 << nr);
}

static inline void reg32_set_bit(u32 addr, int nr)
{
	reg32_modify(addr, 1 << nr, 1 << nr);
}

int sys_gpio_operate(int cmd, const char *name, unsigned int *value)
{
	const struct gpio_pin_mux *G;
	unsigned int reg_offset, reg_dat, gpio_bit;
	u32 reg_mux, reg_ctl, reg_dir;

	G = gpio_name_match(name);
	if (G == NULL)
		return -ENODEV;

	reg_offset = (G->alpha > 'D') ? 0x1c : 0;
	reg_dat = GPIO_BASE + 0xc + reg_offset;
	if (G->alpha > 'D')
		gpio_bit = G->digit + ((G->alpha - 'E') << 3);
	else
		gpio_bit = G->digit + ((G->alpha - 'A') << 3);

	if (cmd == __GPIOSACTIVE)
		cmd = G->active_low ? __GPIOSLOUT : __GPIOSHOUT;
	else if (cmd == __GPIOSINACT)
		cmd = G->active_low ? __GPIOSHOUT : __GPIOSLOUT;

	switch (cmd) {
	case __GPIOGACTIVE:
	case __GPIOGIN:
		*value = !!(REG32(reg_dat) & (1 << gpio_bit)) ^ G->active_low;
		break;
	case __GPIOSHOUT:
	case __GPIOSLOUT:
		reg32_modify(reg_dat, (cmd == __GPIOSHOUT) ? (1 << gpio_bit) : 0, (1 << gpio_bit));
		break;
	case __GPIOCOUT:
	case __GPIOCIN:
	case __GPIODECONF:
#ifdef CONFIG_RTL_8198C
		reg_mux = 0xb8000100 + ((G->pinno - 1) << 2);
#elif defined(CONFIG_RTL_8197F)
		reg_mux = 0xb8000800 + (G->pinno << 2);
#else
# error PINMUX base not defined!
#endif
		reg_ctl = GPIO_BASE + reg_offset;
		reg_dir = GPIO_BASE + 0x8 + reg_offset;
		if (cmd != __GPIODECONF) {
			reg32_modify(reg_mux, G->value << G->offset, ((1 << G->mask_len) - 1) << G->offset);
			reg32_clear_bit(reg_ctl, gpio_bit);
			reg32_modify(reg_dir, (cmd == __GPIOCOUT) ? (1 << gpio_bit) : 0, (1 << gpio_bit));
			if (cmd == __GPIOCOUT && value)
				reg32_modify(reg_dat, *value << gpio_bit, 1 << gpio_bit);
		} else {
			reg32_clear_bit(reg_dir, gpio_bit);
			reg32_set_bit(reg_ctl, gpio_bit);
			reg32_modify(reg_mux, *value << G->offset, ((1 << G->mask_len) - 1) << G->offset);
		}
		break;
	default:
		return -EINVAL;
	}
	return 0;
}
EXPORT_SYMBOL(sys_gpio_operate);

static long brdio_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	unsigned int port;
	int nr;
	int status;
	union {
		unsigned int value[2];
		char name[sizeof(int) << 1];
	} u;

	if (_IOC_TYPE(cmd) != BRDIO_MAJOR)
		return -EINVAL;
	nr = _IOC_NR(cmd);
	switch (nr) {
	case __PHGIO:
	case __PHSIO:
		return brdio_phreq(nr, (struct phreq __user *)arg);
	case __PVIDGET:
		if (copy_from_user(&port, (void *)arg, sizeof(port)))
			return -EFAULT;
		if (rtl8651_getAsicPVlanId(port, &u.value[0]))
			return -EINVAL;
		if (put_user(u.value[0], (int __user *)arg))
			return -EFAULT;
		return 0;
	case __BIOCGETHRX:
	case __BIOCSETHCLRRX:
		return -ENOSYS;
	case __GPIOCOUT:
	case __GPIOCIN:
	case __GPIOSHOUT:
	case __GPIOSLOUT:
	case __GPIOGIN:
	case __GPIODECONF:
		if (copy_from_user(u.value, (void *)arg, sizeof(u.value)))
			return -EFAULT;
		status = sys_gpio_operate(nr, u.name, &u.value[1]);
		if (status == 0 && nr == __GPIOGIN) {
			if (put_user(u.value[1], (int __user *)arg))
				return -EFAULT;
		}
		return status;
	default:
		break;
	}

	return -EINVAL;
}

static int brdio_open(struct inode *inode, struct file *file)
{
	return 0;
}

static int brdio_close(struct inode *inode, struct file *file)
{
	return 0;
}

static ssize_t brdio_read(struct file *filp, char __user * buf, size_t size, loff_t * ppos)
{
	return -ENOSYS;
}

static ssize_t brdio_write(struct file *file, const char __user * user_buf,
			size_t user_len, loff_t * offset)
{
	return -ENOSYS;
}

static struct file_operations brdio_fops = {
	.unlocked_ioctl = brdio_ioctl,
	.open = brdio_open,
	.read = brdio_read,
	.write = brdio_write,
	.release = brdio_close,
};

static int __init private_mkproc(void)
{
	proc_create("brdio", 0644, NULL, &brdio_fops);
	return 0;
}

static void __exit private_rmproc(void)
{
	remove_proc_entry("brdio", NULL);
}

module_init(private_mkproc);
module_exit(private_rmproc);
