/*
 *   rtl_davo_vlan.c: Davolink specific VLAN source
 */
#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,4,0)
#define DRV_RELDATE		"Jan 27, 2014"
#include <linux/kconfig.h>
#else
#define DRV_RELDATE		"Mar 25, 2004"
#include <linux/config.h>
#endif
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/compiler.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/etherdevice.h>
#include <linux/init.h>
#include <linux/pci.h>
#include <linux/delay.h>
#include <linux/ethtool.h>
#include <linux/mii.h>
#include <linux/if_vlan.h>
#include <linux/crc32.h>
#include <asm/io.h>
#include <asm/uaccess.h>
#include <linux/slab.h>
#include <linux/signal.h>
#include <linux/proc_fs.h>
#include <linux/time.h>
#include <linux/rtc.h>
#include <bsp/bspchip.h>
#include <linux/timer.h>
#if defined(CONFIG_RTK_VLAN_SUPPORT)
# include <net/rtl/rtk_vlan.h>
#endif

#if defined(CONFIG_RTL8196_RTL8366) && defined(CONFIG_RTL_IGMP_SNOOPING)
# undef	CONFIG_RTL_IGMP_SNOOPING
#endif

#include "version.h"
#include <net/rtl/rtl_types.h>
#include <net/rtl/rtl_glue.h>

#include "AsicDriver/asicRegs.h"
#include "AsicDriver/rtl865x_asicCom.h"
#include "AsicDriver/rtl865x_asicL2.h"
#ifdef CONFIG_RTL_LAYERED_ASIC_DRIVER_L3
# include "AsicDriver/rtl865x_asicL3.h"
#endif

#include "common/mbuf.h"
#include <net/rtl/rtl_queue.h>
#include "common/rtl_errno.h"
#include "rtl865xc_swNic.h"

/*common*/
#include "common/rtl865x_vlan.h"
#include <net/rtl/rtl865x_netif.h>
#include "common/rtl865x_netif_local.h"

/*l2*/
#ifdef CONFIG_RTL_LAYERED_DRIVER_L2
# include "l2Driver/rtl865x_fdb.h"
# include <net/rtl/rtl865x_fdb_api.h>
#endif

/*l3*/
#ifdef CONFIG_RTL_LAYERED_DRIVER_L3
# include "l3Driver/rtl865x_ip.h"
# include "l3Driver/rtl865x_nexthop.h"
# include <net/rtl/rtl865x_ppp.h>
# include "l3Driver/rtl865x_ppp_local.h"
# include "l3Driver/rtl865x_route.h"
# include "l3Driver/rtl865x_arp.h"
# include <net/rtl/rtl865x_nat.h>
#endif

/*l4*/
#ifdef	CONFIG_RTL865X_ROMEPERF
# include "romeperf.h"
#endif
#include <net/rtl/rtl_nic.h>
#if defined(CONFIG_RTL_HW_QOS_SUPPORT) && defined(CONFIG_NET_SCHED) && defined(CONFIG_RTL_LAYERED_DRIVER)
# include <net/rtl/rtl865x_outputQueue.h>
#endif
//#include <linux/utils2.h>
//#include "dvnv.h"
#include "rtl_davo_vlan.h"

// definitions to avoid redefinition errors
#define TYPEDEF_UINT8
#define TYPEDEF_UINT16
#define TYPEDEF_UINT32
#define TYPEDEF_UINT64
#define TYPEDEF_INT8
#define TYPEDEF_INT16
#define TYPEDEF_INT32
#define TYPEDEF_INT64
#include <bcmnvram.h>

struct vlan_port_info {
	uint16	vlan_id, priority;
	uint16	mbr, tags;
};

struct vlan_port_conf {
	int8_t pvid[VPORT_NUM_MAX];			/* PVID per port which indexes vpi */
	struct vlan_port_info vpi[VPORT_CFG_MAX];	/* lists of VLAN information */
};

int wan_vlan_id;
static struct vlan_port_conf vports;

#include <linux/ctype.h>
static char *st_rtl_trim(char *s)
{
    int len = strlen(s);
    /* trim trailing whitespace and double quotation */
    while (len > 0 && (isspace(s[len - 1]) || s[len - 1] == '"'))
        s[--len] = '\0';
    /* trim trailing whitespace and double quotation */
    memmove(s, &s[strspn(s, " \n\r\t\v\"")], len);
    return s;
}
static int st_rtl_args(char *line, char *ag[], unsigned agsz, const char *delim)
{
    char *q, *p = line;
    unsigned i, ac = 0;

    while ((q = strsep(&p, delim))) {
        st_rtl_trim(q);
        if (*q) {
            if (ac < agsz)
                ag[ac++] = q;
        }
    }
    for (i = ac; i < agsz; i++)
        ag[i] = NULL;
    return (int)ac;
}


static inline char *st_dvnv_get(const char *var, char *buf, int szbuf)
{
	char *p;

	if ((p=nvram_get(var)))
		snprintf(buf, szbuf, "%s", p);
	return p;
}

int vport_read_conf(void)
{
	char buf[32], var[24];
	char *ar[6];
	uint16 vid, mbr;
	int i, c, n;

	/* fill VLAN entries */
	for (i = c = 0; i < VPORT_CFG_MAX; i++) {
		memset(&vports.vpi[i], 0, sizeof(vports.vpi[0]));
		sprintf(var, "x_VLAN_%d", i);
		if (!st_dvnv_get(var, buf, sizeof(buf)) ||
		    (n = st_rtl_args(buf, ar, sizeof(ar) / sizeof(ar[0]), "_")) < 2)
			continue;

		vid = (uint16)simple_strtoul(ar[0], NULL, 0);
		mbr = (uint16)simple_strtoul(ar[1], NULL, 16);
		if (!vid || vid >= 4096 || !(mbr & VPORT_MASK))
			continue;

		vports.vpi[i].vlan_id = vid;
		vports.vpi[i].mbr = mbr;
		if (n > 2)
			vports.vpi[i].tags = mbr & (uint16)simple_strtoul(ar[2], NULL, 16);
		if (n > 3)
			vports.vpi[i].priority = (uint16)simple_strtoul(ar[3], NULL, 16);
		c++;
	}

	for (i = 0; i < VPORT_NUM_MAX; i++) {
		vports.pvid[i] = -1;
		sprintf(var, "x_VLAN_PORT_%d", i);
		if (st_dvnv_get(var, buf, sizeof(buf))) {
			n = simple_strtol(st_rtl_trim(buf), NULL, 0);
			if (n >= 0 && n < VPORT_CFG_MAX &&
			    vports.vpi[n].vlan_id && (vports.vpi[n].mbr & (1 << i))) {
				if (vports.vpi[n].mbr & RTL_LANPORT_MASK)
#if 0
					vports.vpi[n].mbr |= 0x1C0;	/* Extension Port */
#else
					vports.vpi[n].mbr |= 0x100;	/* Extension Port for H624G */
#endif

				vports.pvid[i] = n;
			}
		}
	}

	return c;
}

int vport_apply(void)
{
	struct vlan_port_info *V = &vports.vpi[0];
	int i, res;

	for (i = 0; i < VPORT_CFG_MAX; i++, V++) {
		if (!V->vlan_id)
			continue;
		res = rtl865x_addVlan(V->vlan_id);
		if (res == SUCCESS || res == RTL_EVLANALREADYEXISTS) {
			rtl865x_addVlanPortMember(V->vlan_id, V->mbr);
			if (V->tags)
				rtl865x_setVlanPortTag(V->vlan_id, V->tags, TRUE);
		}

		printk("VLAN_%d %c%c%c%c%c %d [%d]\n", V->vlan_id,
		       (V->mbr & RTL_WANPORT_MASK) ? ((V->tags & RTL_WANPORT_MASK) ? 'T' : 'U') : '-',
		       (V->mbr & RTL_LANPORT_MASK_1) ? ((V->tags & RTL_LANPORT_MASK_1) ? 'T' : 'U') : '-',
		       (V->mbr & RTL_LANPORT_MASK_2) ? ((V->tags & RTL_LANPORT_MASK_2) ? 'T' : 'U') : '-',
		       (V->mbr & RTL_LANPORT_MASK_3) ? ((V->tags & RTL_LANPORT_MASK_3) ? 'T' : 'U') : '-',
		       (V->mbr & RTL_LANPORT_MASK_4) ? ((V->tags & RTL_LANPORT_MASK_4) ? 'T' : 'U') : '-',
		       V->priority, res);
	}

	return 0;
}

static struct rtl865x_vlanConfig *
search_vconf(struct rtl865x_vlanConfig *vconfs, int len,
	     int (*match)(struct rtl865x_vlanConfig *, void *), void *arg)
{
	int i;

	for (i = 0; i < len; i++) {
		if (match(&vconfs[i], arg))
			return &vconfs[i];
	}
	return NULL;
}

static int wan_vconf(struct rtl865x_vlanConfig *vconf, void *unused)
{
	/* vconf's member is the subset or the same of vpi's member */
	return (vconf->if_type == IF_ETHER && vconf->isWan);
}

static inline int issubset(uint16 mbr1, uint16 mbr2)
{
	return !!((mbr1 | mbr2) == mbr2);
}

static int subseteq(struct rtl865x_vlanConfig *vconf, struct vlan_port_info *vpi)
{
	/* vconf's member is the subset or the same of vpi's member */
	return (vconf->if_type == IF_ETHER &&
		issubset(vconf->memPort & VPORT_MASK, vpi->mbr & VPORT_MASK));
}

static int doublembr(struct rtl865x_vlanConfig *vconf, struct vlan_port_info *vpi)
{
	if (subseteq(vconf, vpi))
		return 0;
	if (((vconf->memPort & VPORT_MASK) & (vpi->mbr & VPORT_MASK)))
		return 1;
	return 0;
}

static int emptyslot(struct rtl865x_vlanConfig *vconf, void *unused)
{
	return !!(vconf->if_type == IF_NONE && vconf->memPort == 0);
}

void vport_organize_vconf_table(struct rtl865x_vlanConfig *vconfs, int len)
{
	struct rtl865x_vlanConfig *vconf;
	struct rtl865x_vlanConfig *tmp;
	struct vlan_port_info *vpi;
	uint32 dupmsk = 0;
	int i;
	struct net_device *dev;

	vconf = search_vconf(vconfs, len, (void *)wan_vconf, NULL);
	if (vconf)
		wan_vlan_id = vconf->vid;
	else
		wan_vlan_id = 0;

	for (i = 0; i < VPORT_NUM_MAX; i++) {
		if (vports.pvid[i] < 0)
			continue;

		vpi = &vports.vpi[vports.pvid[i]];
		if (!vpi->vlan_id || (dupmsk & (1 << vports.pvid[i])))
			continue;

		vconf = search_vconf(vconfs, len, (void *)subseteq, (void *)vpi);
		tmp = search_vconf(vconfs, len, (void *)doublembr, (void *)vpi);
		if (!vconf)
			vconf = search_vconf(vconfs, len, emptyslot, NULL);

		if (vconf) {
			vconf->if_type = IF_ETHER;
			vconf->vid = vpi->vlan_id;
			if (vconf->isWan)
				wan_vlan_id = vpi->vlan_id;
			vconf->memPort = vpi->mbr;
			if ((1 << i) & RTL_LANPORT_MASK)
				vconf->memPort |= 0x100;
			vconf->untagSet = vconf->memPort & ~vpi->tags;
			dupmsk |= (1 << vports.pvid[i]);
			if (tmp) {
				tmp->memPort &= ~vpi->mbr;
				tmp->untagSet &= ~vpi->mbr;
			}
			dev = dev_get_by_name(&init_net,
				strcmp((const char *)vconf->ifname, RTL_DRV_LAN_NETIF_NAME) ? (const char *)vconf->ifname : "eth0");
			if (dev) {
				struct dev_priv *dp = (struct dev_priv *)netdev_priv(dev);
				if (dp->dev == dev)	/* sanity check */
					dp->id = vconf->vid;
				dev_put(dev);
			}
		}
	}
}
