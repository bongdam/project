#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/spinlock.h>
#include <linux/sysctl.h>
#include <linux/delay.h>
#include <brdio.h>

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

#if defined (CONFIG_RTL_IGMP_SNOOPING)
/* jihyun@davo 150614 jcode#1 */
#define CONFIG_NEW_IGMP_IMPLEMENTATION	1
# include <net/rtl/rtl865x_igmpsnooping.h>
# include <linux/if_ether.h>
# include <linux/ip.h>
# if defined (CONFIG_RTL_MLD_SNOOPING)
#  include <linux/ipv6.h>
# endif
# include "igmpsnooping/rtl865x_igmpsnooping_local.h"
#endif

extern int32 rtl865xC_setAsicEthernetForceModeRegs(uint32 port, uint32 enForceMode, uint32 forceLink, uint32 forceSpeed, uint32 forceDuplex);
extern int32 rtl8651_setAsicEthernetPHYSpeed(uint32 port, uint32 speed);
extern int32 rtl8651_setAsicEthernetPHYAdvCapality(uint32 port, uint32 capality);
extern int32 rtl8651_setAsicEthernetPHYAutoNeg(uint32 port, uint32 autoneg);
extern int32 rtl8651_setAsicEthernetPHYDuplex(uint32 port, uint32 duplex);
extern int32 rtl8651_setAsicEthernetPHYPowerDown(uint32, uint32);

extern struct stats_ether rx_stats_per_port[5];

union u_var {
	u8 b;
	u16 h;
	u32 w;
};

#define UNALIGNED2(X, Y) \
     (((unsigned int)(X) & (sizeof(unsigned int) - 1)) | \
      ((unsigned int)(Y) & (sizeof(unsigned int) - 1)))

union u_varp {
	volatile u8 *b;		/* single-byte */
	volatile u32 *w;	/* quad-byte */
};

static int brdio_mareq(unsigned int cmd, unsigned long arg)
{
	struct mareq __user *rsp = (struct mareq __user *)arg;
	struct mareq req;
	union u_var var;
	union u_varp p1, p2;

	if (copy_from_user((char *)&req, rsp, sizeof(req)))
		return -EFAULT;

	if (req.mar_len > 0x1000)
		req.mar_len = 0x1000;

	switch (cmd) {
	case __BIO_MD:
		p1.b = (volatile u8 *)rsp->buf;
		p2.b = (volatile u8 *)req.mar_addr;

		if (!UNALIGNED2(p1.b, p2.b)) {
			for (; req.mar_len > 4; req.mar_len -= 4) {
				var.w = *p2.w++;
				if (put_user(var.w, (u32 __user *)p1.w))
					return -EFAULT;
				p1.w++;
			}
		}

		while (req.mar_len-- > 0) {
			var.b = *p2.b++;
			if (put_user(var.b, (u8 __user *)p1.b))
				return -EFAULT;
			p1.b++;
		}
		break;

	case __BIO_MM:
		switch (req.mar_len) {
		case MIO_SIZ_08:
			if (get_user(var.b, (u8 __user *)rsp->buf))
				return -EFAULT;
			*((u8 *)req.mar_addr) = var.b;
			break;

		case MIO_SIZ_16:
			if (get_user(var.h, (u16 __user *)rsp->buf))
				return -EFAULT;
			*((u16 *)req.mar_addr) = var.h;
			break;

		case MIO_SIZ_32:
			if (get_user(var.w, (u32 __user *)rsp->buf))
				return -EFAULT;
			*((u32 *)req.mar_addr) = var.w;
			break;

		default:
			return -EINVAL;
		}
		break;

	default:
		return -EINVAL;
	}

	return 0;
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
#ifdef CONFIG_RTL_8198C
	extern rtl8651_tblAsic_ethernet_t rtl8651AsicEthernetTable[];
#endif
	if (copy_from_user((char *)&phr, arg, sizeof(phr)))
		return -EFAULT;

	if (phr.phr_port < PH_MINPORT || phr.phr_port > PH_MAXPORT)
		return -EINVAL;

	switch (cmd) {
	case __PHGIO:
		phr.phr_optmask = 0;
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
#ifdef CONFIG_RTL_8198C
		/* A real phy-id can be different with phr.phr_port */
		phyid = rtl8651AsicEthernetTable[phr.phr_port].phyId;
#else
		phyid = phr.phr_port;
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
#define PauseFlowControlBitShift	16
#if (PauseFlowControl_MASK != (3 << PauseFlowControlBitShift))
#error PauseFlowControlBitShift MUST be redefined.
#endif
				uint32 nvalue, reg4;

				rvalue = READ_MEM32(PCRP0 + (phr.phr_port << 2)) & PauseFlowControl_MASK;
				if (phr.phr_optmask & PHF_RXPAUSE)
					rxpause = !!(phr.phr_option & PHF_RXPAUSE);
				if (phr.phr_optmask & PHF_TXPAUSE)
					txpause = !!(phr.phr_option & PHF_TXPAUSE);

				switch ((!!txpause << 1) | !!rxpause) {
				case 0:		/* -txpause -rxpause: PAUSE:0 ASM_DIR:0 */
					nvalue = (0 << PauseFlowControlBitShift);
					break;
				case 2:		/* +txpause -rxpause: PAUSE:0 ASM_DIR:1 */
					nvalue = (2 << PauseFlowControlBitShift);
					break;
				default:	/* [+-]txpause +rxpause: PAUSE:1 ASM_DIR:1 */
					nvalue = (3 << PauseFlowControlBitShift);
					break;
				}
				if (nvalue != rvalue) {
					rtl8651_getAsicEthernetPHYReg(phyid, 4, &reg4);
					reg4 &= ~(3 << 10);
					rtl8651_setAsicEthernetPHYReg(phyid, 4, reg4 | ((nvalue >> PauseFlowControlBitShift) << 10));
					rtl865xC_setAsicPortPauseFlowControl(phr.phr_port,
						!!(nvalue & (2 << PauseFlowControlBitShift)),	/* ASM_DIR */
						!!(nvalue & (1 << PauseFlowControlBitShift)));	/* PAUSE */
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

#if defined (CONFIG_RTL_IGMP_SNOOPING)
/* jihyun@davo 150614 jcode#1 */
extern uint32 nicIgmpModuleIndex;
extern uint32 rtl_sysUpSeconds;

extern struct rtl_groupEntry* rtl_searchGroupEntry(uint32 moduleIndex, uint32 ipVersion,uint32 *multicastAddr);

static struct rtl_sourceEntry *
rtl_matchsource(uint32 ipVersion, uint32 *saddr, struct rtl_clientEntry *clnt)
{
	struct rtl_sourceEntry *source;

	for (source = clnt->sourceList; source; source = source->next) {
		if (ipVersion == IP_VERSION4) {
			if (saddr[0] == source->sourceAddr[0])
				return source;
		}
#ifdef CONFIG_RTL_MLD_SNOOPING
		else if ((saddr[0] == source->sourceAddr[0]) &&
			 (saddr[1] == source->sourceAddr[1]) &&
			 (saddr[2] == source->sourceAddr[2]) &&
			 (saddr[3] == source->sourceAddr[3]))
			return source;
#endif
	}
	return NULL;
}

static int brdio_mcfwdreq(unsigned int cmd, unsigned long arg)
{
#if defined (CONFIG_RTL_IGMP_SNOOPING)
	struct mcfwd_req __user *rsp = (struct mcfwd_req __user *)arg;
	struct mcfwd_req req;
	struct rtl_groupEntry *grp;
	struct rtl_clientEntry *clnt;
	struct rtl_sourceEntry *source;

	if (copy_from_user((char *)&req, rsp, sizeof(req)))
		return -EFAULT;
	req.fwdmask = 0;
	req.port_no = -1;
	grp = rtl_searchGroupEntry(nicIgmpModuleIndex, IP_VERSION4, &req.group);
	if (grp == NULL)
		goto out;

	for (clnt = grp->clientList; clnt; clnt = clnt->next) {
		if (clnt->clientAddr[0] == req.source)
			req.port_no = clnt->portNum;

		source = rtl_matchsource(IP_VERSION4, &req.source, clnt);
		if (clnt->groupFilterTimer <= rtl_sysUpSeconds) {
			/* INCLUDE mode */
			if (source && (source->portTimer > rtl_sysUpSeconds))
				req.fwdmask |= (1 << clnt->portNum);

		} else if (!source || (source->portTimer > rtl_sysUpSeconds)) {
			/* EXCLUDE mode */
			req.fwdmask |= (1 << clnt->portNum);
		}
	}

 out:
	if (put_user(req.fwdmask, (int __user *)&rsp->fwdmask) ||
	    put_user(req.port_no, (int __user *)&rsp->port_no))
		return -EFAULT;
#endif
	return 0;
}
#endif

static long brdio_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	unsigned int port, pvid;
	int nr;
	int status;

	if (_IOC_TYPE(cmd) != BRDIO_MAJOR)
		return -EINVAL;
	nr = _IOC_NR(cmd);
	switch (nr) {
	case __BIO_MD:
	case __BIO_MM:
		return brdio_mareq(nr, arg);
	case __PHGIO:
	case __PHSIO:
		return brdio_phreq(nr, (struct phreq __user *)arg);
	case __PVIDGET:
		if (copy_from_user(&port, (void *)arg, sizeof(port)))
			return -EFAULT;
		if (rtl8651_getAsicPVlanId(port, &pvid))
			return -EINVAL;
		if (put_user(pvid, (int __user *)arg))
			return -EFAULT;
		return 0;
	case __BIOCGETHRX:
		if (copy_to_user((void *)arg, rx_stats_per_port, sizeof(rx_stats_per_port)))
			return -EFAULT;
		return 0;
	case __BIOCSETHCLRRX:
		memset(rx_stats_per_port, 0, sizeof(rx_stats_per_port));
		return 0;
#if defined (CONFIG_RTL_IGMP_SNOOPING)
/* jihyun@davo 150614 jcode#1 */
	case __MCFWD_MASK:
		local_bh_disable();
		status = brdio_mcfwdreq(cmd, arg);
		local_bh_enable();
		return status;
		break;
#endif
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
 unlocked_ioctl:brdio_ioctl,
 open:	brdio_open,
 read:	brdio_read,
 write: brdio_write,
 release:brdio_close
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
