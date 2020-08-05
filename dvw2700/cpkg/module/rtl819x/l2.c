#include <linux/kernel.h>
#include <linux/workqueue.h>
#include <linux/timer.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/netdevice.h>
#include <uapi/linux/if.h>
#include <uapi/linux/in.h>
#include <net/net_namespace.h>

#include "version.h"
#include <net/rtl/rtl_types.h>
#include <net/rtl/rtl_glue.h>
#include <net/rtl/rtl865x_netif.h>
#include "AsicDriver/rtl865x_asicBasic.h"
#include "AsicDriver/rtl865x_asicCom.h"
#include "AsicDriver/rtl865x_asicL2.h"
#ifdef CONFIG_RTL_LAYERED_ASIC_DRIVER_L3
#include "AsicDriver/rtl865x_asicL3.h"
#endif
#include <net/rtl/rtl_queue.h>
#if defined(CONFIG_RTL_LAYERED_ASIC_DRIVER_L4)
#include "AsicDriver/rtl865x_asicL4.h"
#endif
#ifdef CONFIG_RTL_LAYERED_DRIVER_L2
#include "l2Driver/rtl865x_fdb.h"
#include <net/rtl/rtl865x_fdb_api.h>
#endif
#include "AsicDriver/asicRegs.h"

extern int rtl_ll_lookup(const u8 *addr, rtl865x_tblAsicDrv_l2Param_t *l2, u16 fid, u32 *mat);

int rtl_sync_l2_wlsta(const u8 *addr)
{
	rtl865x_tblAsicDrv_l2Param_t l2;
	u32 mat;

	if (rtl_ll_lookup(addr, &l2, RTL_LAN_FID, &mat)
#if (RTL_LAN_FID != RTL_WAN_FID)
	    && rtl_ll_lookup(addr, &l2, RTL_WAN_FID, &mat)
#endif
	   )
		return -1;
	return rtl8651_delAsicL2Table((mat >> 16), (mat & 0xffff));
}

long l2_proc_ioctl(struct file *file, unsigned int command, unsigned long arg)
{
	rtl865x_tblAsicDrv_l2Param_t l2;
	u8 addr[6];
	int resp[2];

	if (_IOC_TYPE(command) != 211)
		return -EINVAL;

	switch (_IOC_NR(command)) {
	case 0:
		if (copy_from_user(addr, (void *)arg, 6))
			return -EFAULT;
		if (!rtl_ll_lookup(addr, &l2, RTL_LAN_FID, NULL)
#if (RTL_LAN_FID != RTL_WAN_FID)
		    || !rtl_ll_lookup(addr, &l2, RTL_WAN_FID, NULL)
#endif
		   ) {
			resp[0] = rtl865x_ConvertPortMasktoPortNum(l2.memberPortMask);
			resp[1] = l2.ageSec;
			return copy_to_user((int *)arg, resp, sizeof(resp));
		}
		return -ENOENT;
	default:
		break;
	}
	return -EINVAL;
}
