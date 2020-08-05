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
#if defined(CONFIG_RTL_LAYERED_ASIC_DRIVER_L4)
#include "AsicDriver/rtl865x_asicL4.h"
#endif
#include "AsicDriver/asicRegs.h"
#include <acl_write.h>
#include <kdmsg.h>

enum {
	TACL_ADD = 0,
	TACL_DEL = 1,
	TACL_FREE = 2
};

struct tail_aclrule {
	struct list_head  list;
	rtl865x_AclRule_t rule;
	char 		  name[IFNAMSIZ];
	int		  chain;
};

static LIST_HEAD(tailq_aclrule);

static int aclrule_enque_tail(rtl865x_AclRule_t *r, const char *name,
			      int chain, int direction, int deletion)
{
	struct tail_aclrule *t, *tmp;
	/* simple sanity check */
	if (deletion == TACL_ADD) {
		if (r == NULL || name == NULL || chain == 100)
			return -EINVAL;
	}
	/* iterate to find the duplicate */
	list_for_each_entry_safe(t, tmp, &tailq_aclrule, list) {
		if ((r == NULL || !memcmp(r, &t->rule, sizeof(*r))) &&
		    (name == NULL || !strcmp(name, t->name)) &&
		    (chain == 100 || chain == t->chain) &&
		    (direction == -1 || direction == t->rule.direction_)) {
		    	if (deletion != TACL_ADD) {
			    	list_del(&t->list);
			    	if (deletion == TACL_DEL)
			    		rtl865x_del_acl(&t->rule, t->name, t->chain);
			    	kfree(t);
			} else
				return -EEXIST;
		}
	}

	if (deletion == TACL_ADD) {
		t = (struct tail_aclrule *)kmalloc(sizeof(*t), GFP_ATOMIC);
		if (t == NULL)
			return -ENOMEM;
		memcpy(&t->rule, r, sizeof(*r));
		strcpy(t->name, name);
		t->chain = chain;
		list_add_tail(&t->list, &tailq_aclrule);
	}

	return 0;
}

int aclrule_keep_at_tail(const char *name, int chain, int direction)
{
	struct tail_aclrule *t;

	/* flush rules in ASIC */
	list_for_each_entry(t, &tailq_aclrule, list) {
		if ((name == NULL || !strcmp(name, t->name)) &&
		    (chain == 100 || chain == t->chain) &&
		    (direction == -1 || direction == t->rule.direction_))
			rtl865x_del_acl(&t->rule, t->name, t->chain);
	}
	list_for_each_entry(t, &tailq_aclrule, list) {
		if ((name == NULL || !strcmp(name, t->name)) &&
		    (chain == 100 || chain == t->chain) &&
		    (direction == -1 || direction == t->rule.direction_))
			rtl865x_add_acl(&t->rule, t->name, t->chain);
	}
	return 0;
}

static int acl_show(struct seq_file *s, void *v)
{
	int8 *actionT[] = {
		"permit",
		"redirect to ether",
		"drop",
		"to cpu",
		"legacy drop",
		"drop for log",
		"mirror",
		"redirect to pppoe",
		"default redirect",
		"mirror keep match",
		"drop rate exceed pps",
		"log rate exceed pps",
		"drop rate exceed bps",
		"log rate exceed bps",
		"priority "
#if defined(CONFIG_RTL_8198C)
		, "change vid"
#endif
	};
#ifdef CONFIG_RTL_LAYERED_DRIVER
	rtl865x_AclRule_t asic_acl;
# if defined(CONFIG_RTL_8198C)
	rtl865x_AclRule_t asic_acl2;
	uint32 acl_temp = 0;
# endif
#else
	_rtl8651_tblDrvAclRule_t asic_acl;
#endif
	rtl865x_tblAsicDrv_intfParam_t asic_intf;
	uint32 acl_start, acl_end;

	uint16 vid;
	int8 outRule;
#if defined(CONFIG_RTL_LOCAL_PUBLIC) || defined(CONFIG_RTL_MULTIPLE_WAN) || defined(CONFIG_RTL_HW_VLAN_SUPPORT)
	unsigned char defInAclStart, defInAclEnd, defOutAclStart, defOutAclEnd;
#endif

	seq_printf(s, "%s\n", "ASIC ACL Table:");
	for (vid = 0; vid < 8; vid++) {
		/* Read VLAN Table */
		if (rtl8651_getAsicNetInterface(vid, &asic_intf) == FAILED)
			continue;
		if (asic_intf.valid == FALSE)
			continue;

		outRule = FALSE;
		acl_start = asic_intf.inAclStart;
		acl_end = asic_intf.inAclEnd;
		seq_printf(s, "\nacl_start(%d), acl_end(%d)", acl_start, acl_end);
 again:
		if (outRule == FALSE)
			seq_printf(s, "\n<<Ingress Rule for Netif  %d: (VID %d)>>\n", vid, asic_intf.vid);
		else
			seq_printf(s, "\n<<Egress Rule for Netif %d (VID %d)>>:\n", vid, asic_intf.vid);

#ifdef CONFIG_RTL_LAYERED_DRIVER
		for (; acl_start <= acl_end; acl_start++) {
			if (_rtl865x_getAclFromAsic(acl_start, &asic_acl) == FAILED)
				seq_printf(s, "Failed to get %d entry(%d).\n", acl_start, __LINE__);

			switch (asic_acl.ruleType_) {
			case RTL865X_ACL_MAC:
				seq_printf(s, " [%d] rule type: %s   rule action: %s\n", acl_start, "Ethernet",
					   actionT[asic_acl.actionType_]);
				seq_printf(s, "\tether type: %x   ether type mask: %x\n", asic_acl.typeLen_,
					   asic_acl.typeLenMask_);
				seq_printf(s, "\tDMAC: %pM  DMACM: %pM\n",
					   asic_acl.dstMac_.octet, asic_acl.dstMacMask_.octet);

				seq_printf(s, "\tSMAC: %pM  SMACM: %pM\n",
					   asic_acl.srcMac_.octet, asic_acl.srcMacMask_.octet);
				break;

			case RTL865X_ACL_IP:
				seq_printf(s, " [%d] rule type: %s   rule action: %s\n", acl_start, "IP",
					   actionT[asic_acl.actionType_]);
				seq_printf(s, "\tdip: %pI4 dipM: %pI4\n",
					   &asic_acl.dstIpAddr_, &asic_acl.dstIpAddrMask_);
				seq_printf(s, "\tsip: %pI4 sipM: %pI4\n",
					   &asic_acl.srcIpAddr_, &asic_acl.srcIpAddrMask_);
				seq_printf(s, "\tTos: %x   TosM: %x   ipProto: %x   ipProtoM: %x   ipFlag: %x   ipFlagM: %x\n",
					   asic_acl.tos_, asic_acl.tosMask_, asic_acl.ipProto_, asic_acl.ipProtoMask_,
					   asic_acl.ipFlag_, asic_acl.ipFlagMask_);

				seq_printf(s, "\t<FOP:%x> <FOM:%x> <http:%x> <httpM:%x> <IdentSdip:%x> <IdentSdipM:%x> \n",
					   asic_acl.ipFOP_, asic_acl.ipFOM_, asic_acl.ipHttpFilter_, asic_acl.ipHttpFilterM_,
					   asic_acl.ipIdentSrcDstIp_, asic_acl.ipIdentSrcDstIpM_);
				seq_printf(s, "\t<DF:%x> <MF:%x>\n", asic_acl.ipDF_, asic_acl.ipMF_);
				break;

			case RTL865X_ACL_IP_RANGE:
				seq_printf(s, " [%d] rule type: %s   rule action: %s\n", acl_start, "IP Range",
					   actionT[asic_acl.actionType_]);
				seq_printf(s, "\tdipU: %pI4 dipL: %pI4\n", &asic_acl.dstIpAddr_,
					   &asic_acl.dstIpAddrMask_);
				seq_printf(s, "\tsipU: %pI4 sipL: %pI4\n", &asic_acl.srcIpAddr_,
					   &asic_acl.srcIpAddrMask_);
				seq_printf(s, "\tTos: %x   TosM: %x   ipProto: %x   ipProtoM: %x   ipFlag: %x   ipFlagM: %x\n",
					   asic_acl.tos_, asic_acl.tosMask_, asic_acl.ipProto_, asic_acl.ipProtoMask_,
					   asic_acl.ipFlag_, asic_acl.ipFlagMask_);
				seq_printf(s, "\t<FOP:%x> <FOM:%x> <http:%x> <httpM:%x> <IdentSdip:%x> <IdentSdipM:%x> \n",
					   asic_acl.ipFOP_, asic_acl.ipFOM_, asic_acl.ipHttpFilter_, asic_acl.ipHttpFilterM_,
					   asic_acl.ipIdentSrcDstIp_, asic_acl.ipIdentSrcDstIpM_);
				seq_printf(s, "\t<DF:%x> <MF:%x>\n", asic_acl.ipDF_, asic_acl.ipMF_);
				break;
			case RTL865X_ACL_ICMP:
				seq_printf(s, " [%d] rule type: %s   rule action: %s\n", acl_start, "ICMP",
					   actionT[asic_acl.actionType_]);
				seq_printf(s, "\tdip: %pI4 dipM: %pI4\n", &asic_acl.dstIpAddr_,
					   &asic_acl.dstIpAddrMask_);
				seq_printf(s, "\tsip: %pI4 sipM: %pI4\n", &asic_acl.srcIpAddr_,
					   &asic_acl.srcIpAddrMask_);
				seq_printf(s, "\tTos: %x   TosM: %x   type: %x   typeM: %x   code: %x   codeM: %x\n",
					   asic_acl.tos_, asic_acl.tosMask_, asic_acl.icmpType_, asic_acl.icmpTypeMask_,
					   asic_acl.icmpCode_, asic_acl.icmpCodeMask_);
				break;
			case RTL865X_ACL_ICMP_IPRANGE:
				seq_printf(s, " [%d] rule type: %s   rule action: %s\n", acl_start, "ICMP IP RANGE",
					   actionT[asic_acl.actionType_]);
				seq_printf(s, "\tdipU: %pI4 dipL: %pI4\n", &asic_acl.dstIpAddr_,
					   &asic_acl.dstIpAddrMask_);
				seq_printf(s, "\tsipU: %pI4 sipL: %pI4\n", &asic_acl.srcIpAddr_,
					   &asic_acl.srcIpAddrMask_);
				seq_printf(s, "\tTos: %x   TosM: %x   type: %x   typeM: %x   code: %x   codeM: %x\n",
					   asic_acl.tos_, asic_acl.tosMask_, asic_acl.icmpType_, asic_acl.icmpTypeMask_,
					   asic_acl.icmpCode_, asic_acl.icmpCodeMask_);
				break;
			case RTL865X_ACL_IGMP:
				seq_printf(s, " [%d] rule type: %s   rule action: %s\n", acl_start, "IGMP",
					   actionT[asic_acl.actionType_]);
				seq_printf(s, "\tdip: %pI4 dipM: %pI4\n", &asic_acl.dstIpAddr_,
					   &asic_acl.dstIpAddrMask_);
				seq_printf(s, "\tsip: %pI4 sipM: %pI4\n", &asic_acl.srcIpAddr_,
					   &asic_acl.srcIpAddrMask_);
				seq_printf(s, "\tTos: %x   TosM: %x   type: %x   typeM: %x\n", asic_acl.tos_, asic_acl.tosMask_,
					   asic_acl.igmpType_, asic_acl.igmpTypeMask_);
				break;

			case RTL865X_ACL_IGMP_IPRANGE:
				seq_printf(s, " [%d] rule type: %s   rule action: %s\n", acl_start, "IGMP IP RANGE",
					   actionT[asic_acl.actionType_]);
				seq_printf(s, "\tdip: %pI4 dipM: %pI4\n", &asic_acl.dstIpAddr_,
					   &asic_acl.dstIpAddrMask_);
				seq_printf(s, "\tsip: %pI4 sipM: %pI4\n", &asic_acl.srcIpAddr_,
					   &asic_acl.srcIpAddrMask_);
				seq_printf(s, "\tTos: %x   TosM: %x   type: %x   typeM: %x\n", asic_acl.tos_, asic_acl.tosMask_,
					   asic_acl.igmpType_, asic_acl.igmpTypeMask_);
				break;

			case RTL865X_ACL_TCP:
				seq_printf(s, " [%d] rule type: %s   rule action: %s\n", acl_start, "TCP",
					   actionT[asic_acl.actionType_]);
				seq_printf(s, "\tdip: %pI4 dipM: %pI4\n", &asic_acl.dstIpAddr_,
					   &asic_acl.dstIpAddrMask_);
				seq_printf(s, "\tsip: %pI4 sipM: %pI4\n", &asic_acl.srcIpAddr_,
					   &asic_acl.srcIpAddrMask_);
				seq_printf(s, "\tTos:%x  TosM:%x  sportL:%d  sportU:%d  dportL:%d  dportU:%d\n",
					   asic_acl.tos_, asic_acl.tosMask_, asic_acl.tcpSrcPortLB_, asic_acl.tcpSrcPortUB_,
					   asic_acl.tcpDstPortLB_, asic_acl.tcpDstPortUB_);
				seq_printf(s, "\tflag: %x  flagM: %x  <URG:%x> <ACK:%x> <PSH:%x> <RST:%x> <SYN:%x> <FIN:%x>\n",
					   asic_acl.tcpFlag_, asic_acl.tcpFlagMask_, asic_acl.tcpURG_, asic_acl.tcpACK_,
					   asic_acl.tcpPSH_, asic_acl.tcpRST_, asic_acl.tcpSYN_, asic_acl.tcpFIN_);
				break;
			case RTL865X_ACL_TCP_IPRANGE:
				seq_printf(s, " [%d] rule type: %s   rule action: %s\n", acl_start, "TCP IP RANGE",
					   actionT[asic_acl.actionType_]);
				seq_printf(s, "\tdipU: %pI4 dipL: %pI4\n", &asic_acl.dstIpAddr_,
					   &asic_acl.dstIpAddrMask_);
				seq_printf(s, "\tsipU: %pI4 sipL: %pI4\n", &asic_acl.srcIpAddr_,
					   &asic_acl.srcIpAddrMask_);
				seq_printf(s, "\tTos:%x  TosM:%x  sportL:%d  sportU:%d  dportL:%d  dportU:%d\n",
					   asic_acl.tos_, asic_acl.tosMask_, asic_acl.tcpSrcPortLB_, asic_acl.tcpSrcPortUB_,
					   asic_acl.tcpDstPortLB_, asic_acl.tcpDstPortUB_);
				seq_printf(s, "\tflag: %x  flagM: %x  <URG:%x> <ACK:%x> <PSH:%x> <RST:%x> <SYN:%x> <FIN:%x>\n",
					   asic_acl.tcpFlag_, asic_acl.tcpFlagMask_, asic_acl.tcpURG_, asic_acl.tcpACK_,
					   asic_acl.tcpPSH_, asic_acl.tcpRST_, asic_acl.tcpSYN_, asic_acl.tcpFIN_);
				break;

			case RTL865X_ACL_UDP:
				seq_printf(s, " [%d] rule type: %s   rule action: %s\n", acl_start, "UDP",
					   actionT[asic_acl.actionType_]);
				seq_printf(s, "\tdip: %pI4 dipM: %pI4\n", &asic_acl.dstIpAddr_,
					   &asic_acl.dstIpAddrMask_);
				seq_printf(s, "\tsip: %pI4 sipM: %pI4\n", &asic_acl.srcIpAddr_,
					   &asic_acl.srcIpAddrMask_);
				seq_printf(s, "\tTos:%x  TosM:%x  sportL:%d  sportU:%d  dportL:%d  dportU:%d\n",
					   asic_acl.tos_, asic_acl.tosMask_, asic_acl.udpSrcPortLB_, asic_acl.udpSrcPortUB_,
					   asic_acl.udpDstPortLB_, asic_acl.udpDstPortUB_);
				break;
			case RTL865X_ACL_UDP_IPRANGE:
				seq_printf(s, " [%d] rule type: %s   rule action: %s\n", acl_start, "UDP IP RANGE",
					   actionT[asic_acl.actionType_]);
				seq_printf(s, "\tdipU: %pI4 dipL: %pI4\n", &asic_acl.dstIpAddr_,
					   &asic_acl.dstIpAddrMask_);
				seq_printf(s, "\tsipU: %pI4 sipL: %pI4\n", &asic_acl.srcIpAddr_,
					   &asic_acl.srcIpAddrMask_);
				seq_printf(s, "\tTos:%x  TosM:%x  sportL:%d  sportU:%d  dportL:%d  dportU:%d\n",
					   asic_acl.tos_, asic_acl.tosMask_, asic_acl.udpSrcPortLB_, asic_acl.udpSrcPortUB_,
					   asic_acl.udpDstPortLB_, asic_acl.udpDstPortUB_);
				break;

			case RTL865X_ACL_SRCFILTER:
				seq_printf(s, " [%d] rule type: %s   rule action: %s\n", acl_start, "Source Filter",
					   actionT[asic_acl.actionType_]);
				seq_printf(s, "\tSMAC: %pM  SMACM: %pM\n",
					   asic_acl.srcFilterMac_.octet, asic_acl.srcFilterMacMask_.octet);
				seq_printf(s, "\tsvidx: %d   svidxM: %x   sport: %d   sportM: %x   ProtoType: %x\n",
					   asic_acl.srcFilterVlanIdx_, asic_acl.srcFilterVlanIdxMask_, asic_acl.srcFilterPort_,
					   asic_acl.srcFilterPortMask_,
					   (asic_acl.srcFilterIgnoreL3L4_ ==
					    TRUE ? 2 : (asic_acl.srcFilterIgnoreL4_ == 1 ? 1 : 0))
				    );
				seq_printf(s, "\tsip: %pI4   sipM: %pI4\n", &asic_acl.srcFilterIpAddr_,
					   &asic_acl.srcFilterIpAddrMask_);
				seq_printf(s, "\tsportL: %d   sportU: %d\n", asic_acl.srcFilterPortLowerBound_,
					   asic_acl.srcFilterPortUpperBound_);
				break;

			case RTL865X_ACL_SRCFILTER_IPRANGE:
				seq_printf(s, " [%d] rule type: %s   rule action: %s\n", acl_start, "Source Filter(IP RANGE)",
					   actionT[asic_acl.actionType_]);
				seq_printf(s, "\tSMAC: %pM  SMACM: %pM\n",
					   asic_acl.srcFilterMac_.octet, asic_acl.srcFilterMacMask_.octet);
				seq_printf(s, "\tsvidx: %d   svidxM: %x   sport: %d   sportM: %x   ProtoType: %x\n",
					   asic_acl.srcFilterVlanIdx_, asic_acl.srcFilterVlanIdxMask_, asic_acl.srcFilterPort_,
					   asic_acl.srcFilterPortMask_,
					   (asic_acl.srcFilterIgnoreL3L4_ ==
					    TRUE ? 2 : (asic_acl.srcFilterIgnoreL4_ == 1 ? 1 : 0))
				    );
				seq_printf(s, "\tsipU: %pI4   sipL: %pI4\n", &asic_acl.srcFilterIpAddr_,
					   &asic_acl.srcFilterIpAddrMask_);
				seq_printf(s, "\tsportL: %d   sportU: %d\n", asic_acl.srcFilterPortLowerBound_,
					   asic_acl.srcFilterPortUpperBound_);
				break;

			case RTL865X_ACL_DSTFILTER:
				seq_printf(s, " [%d] rule type: %s   rule action: %s\n", acl_start, "Deatination Filter",
					   actionT[asic_acl.actionType_]);
				seq_printf(s, "\tDMAC: %pM  DMACM: %pM\n",
					   asic_acl.dstFilterMac_.octet, asic_acl.dstFilterMacMask_.octet);
				seq_printf(s, "\tdvidx: %d   dvidxM: %x  ProtoType: %x   dportL: %d   dportU: %d\n",
					   asic_acl.dstFilterVlanIdx_, asic_acl.dstFilterVlanIdxMask_,
					   (asic_acl.dstFilterIgnoreL3L4_ ==
					    TRUE ? 2 : (asic_acl.dstFilterIgnoreL4_ == 1 ? 1 : 0)),
					   asic_acl.dstFilterPortLowerBound_, asic_acl.dstFilterPortUpperBound_);
				seq_printf(s, "\tdip: %pI4   dipM: %pI4\n", &asic_acl.dstFilterIpAddr_,
					   &asic_acl.dstFilterIpAddrMask_);
				break;
			case RTL865X_ACL_DSTFILTER_IPRANGE:
				seq_printf(s, " [%d] rule type: %s   rule action: %s\n", acl_start,
					   "Deatination Filter(IP Range)", actionT[asic_acl.actionType_]);
				seq_printf(s, "\tDMAC: %pM  DMACM: %pM\n",
					   asic_acl.dstFilterMac_.octet, asic_acl.dstFilterMacMask_.octet);
				seq_printf(s, "\tdvidx: %d   dvidxM: %x  ProtoType: %x   dportL: %d   dportU: %d\n",
					   asic_acl.dstFilterVlanIdx_, asic_acl.dstFilterVlanIdxMask_,
					   (asic_acl.dstFilterIgnoreL3L4_ ==
					    TRUE ? 2 : (asic_acl.dstFilterIgnoreL4_ == 1 ? 1 : 0)),
					   asic_acl.dstFilterPortLowerBound_, asic_acl.dstFilterPortUpperBound_);
				seq_printf(s, "\tdipU: %pI4   dipL: %pI4\n", &asic_acl.dstFilterIpAddr_,
					   &asic_acl.dstFilterIpAddrMask_);
				break;

# if defined(CONFIG_RTL_8198C)
			case RTL865X_ACL_IPV6:	/* IP Rule Type: 0x0010 */
			case RTL865X_ACL_IPV6_RANGE:
				/* a ipv6 rule occupied  two entry, function _rtl865x_getAclFromAsic take one entry at a time,
				 * so, need to call function _rtl865x_getAclFromAsic again.
				 */
				acl_temp = acl_start;
				acl_temp++;
				if (acl_temp <= acl_end)	//the second entry index of ipv6 rule, should  less than or equal to acl_end.
				{
					memset(&asic_acl2, 0x00, sizeof(rtl865x_AclRule_t));
					if (_rtl865x_getAclFromAsic(acl_temp, &asic_acl2) == FAILED)
						seq_printf(s, "Failed to get %d entry(%d).\n", acl_temp, __LINE__);

					if ((!asic_acl2.ipv6EntryType_) && asic_acl.ipv6EntryType_) {
						asic_acl.dstIpV6Addr_.v6_addr32[3] = asic_acl2.dstIpV6Addr_.v6_addr32[3];
						asic_acl.dstIpV6Addr_.v6_addr32[2] = asic_acl2.dstIpV6Addr_.v6_addr32[2];
						asic_acl.dstIpV6Addr_.v6_addr32[1] = asic_acl2.dstIpV6Addr_.v6_addr32[1];
						asic_acl.dstIpV6Addr_.v6_addr32[0] = asic_acl2.dstIpV6Addr_.v6_addr32[0];

						asic_acl.dstIpV6AddrMask_.v6_addr32[3] =
						    asic_acl2.dstIpV6AddrMask_.v6_addr32[3];
						asic_acl.dstIpV6AddrMask_.v6_addr32[2] =
						    asic_acl2.dstIpV6AddrMask_.v6_addr32[2];
						asic_acl.dstIpV6AddrMask_.v6_addr32[1] =
						    asic_acl2.dstIpV6AddrMask_.v6_addr32[1];
						asic_acl.dstIpV6AddrMask_.v6_addr32[0] =
						    asic_acl2.dstIpV6AddrMask_.v6_addr32[0];

						asic_acl.ipv6TrafficClass_ = asic_acl2.ipv6TrafficClass_;
						asic_acl.ipv6TrafficClassM_ = asic_acl2.ipv6TrafficClassM_;
						asic_acl.ipv6NextHeader_ = asic_acl2.ipv6NextHeader_;
						asic_acl.ipv6NextHeaderM_ = asic_acl2.ipv6NextHeaderM_;
						asic_acl.ipv6HttpFilter_ = asic_acl2.ipv6HttpFilter_;
						asic_acl.ipv6HttpFilterM_ = asic_acl2.ipv6HttpFilterM_;
						asic_acl.ipv6IdentSrcDstIp_ = asic_acl2.ipv6IdentSrcDstIp_;
						asic_acl.ipv6IdentSrcDstIpM_ = asic_acl2.ipv6IdentSrcDstIpM_;
						/* ActionType and ActionField useless in entry0 */
						asic_acl.actionType_ = asic_acl2.actionType_;
						switch (asic_acl.actionType_) {

						case RTL865X_ACL_PERMIT:
						case RTL865X_ACL_REDIRECT_ETHER:
						case RTL865X_ACL_DROP:
						case RTL865X_ACL_TOCPU:
						case RTL865X_ACL_LEGACY_DROP:
						case RTL865X_ACL_DROPCPU_LOG:
						case RTL865X_ACL_MIRROR:
						case RTL865X_ACL_REDIRECT_PPPOE:
						case RTL865X_ACL_MIRROR_KEEP_MATCH:
							asic_acl.L2Idx_ = asic_acl2.L2Idx_;
							asic_acl.netifIdx_ = asic_acl2.netifIdx_;
							asic_acl.pppoeIdx_ = asic_acl2.pppoeIdx_;
							break;

						case RTL865X_ACL_DEFAULT_REDIRECT:
							asic_acl.nexthopIdx_ = asic_acl2.nexthopIdx_;
							break;

						case RTL865X_ACL_DROP_RATE_EXCEED_PPS:
						case RTL865X_ACL_LOG_RATE_EXCEED_PPS:
						case RTL865X_ACL_DROP_RATE_EXCEED_BPS:
						case RTL865X_ACL_LOG_RATE_EXCEED_BPS:
							asic_acl.ratelimtIdx_ = asic_acl2.ratelimtIdx_;
							break;
						case RTL865X_ACL_PRIORITY:
							asic_acl.priority_ = asic_acl2.priority_;
							break;
						case RTL865X_ACL_VID:
							asic_acl.aclvid_ = asic_acl2.aclvid_;
							break;
						}
						/* INV useless in entry 0 */
						asic_acl.ipv6Invert_ = asic_acl2.ipv6Invert_;
						//asic_acl.ipv6Combine_  = asic_acl2.ipv6Combine_ ;
						//asic_acl.ipv6IPtunnel_ = asic_acl2.ipv6IPtunnel_;
						seq_printf(s, " [%d-%d] rule type: %s   rule action: %s\n", acl_start, acl_temp,
							   "IPv6", actionT[asic_acl.actionType_]);
						if (RTL865X_ACL_IPV6 == asic_acl.ruleType_) {
							seq_printf(s, "\tsip: %pI6c  sipM: %pI6c\n",
								   asic_acl.srcIpV6Addr_.v6_addr16, asic_acl.srcIpV6AddrMask_.v6_addr16);
							seq_printf(s, "\tdip: %pI6c  dipM: %pI6c\n",
								   asic_acl.dstIpV6Addr_.v6_addr16, asic_acl.dstIpV6AddrMask_.v6_addr16);

						} else if (RTL865X_ACL_IPV6_RANGE == asic_acl.ruleType_) {
							seq_printf(s, "\tsipLB: %pI6c  sipUB: %pI6c\n",
								   asic_acl.srcIpV6AddrLB_.v6_addr16, asic_acl.srcIpV6AddrUB_.v6_addr16);
							seq_printf(s, "\tdipLB: %pI6c  dipUB: %pI6c\n",
								   asic_acl.dstIpV6AddrLB_.v6_addr16, asic_acl.dstIpV6AddrUB_.v6_addr16);
						}
						seq_printf(s, "\tFlowLabel: 0x%x   FlowLabelM: 0x%x\n",
							   asic_acl.ipv6FlowLabel_, asic_acl.ipv6FlowLabelM_);
						seq_printf(s, "\tInvert: %d   Combine: %d   IPtunnel: %d\n",
							   asic_acl.ipv6Invert_, asic_acl.ipv6Combine_, asic_acl.ipv6IPtunnel_);
						seq_printf(s,
							   "\tTrafficClassP: %d   TrafficClassM: %d   NextHeaderP: %d   NextHeaderM: %d\n",
							   asic_acl.ipv6TrafficClass_, asic_acl.ipv6TrafficClassM_,
							   asic_acl.ipv6NextHeader_, asic_acl.ipv6NextHeaderM_);
						seq_printf(s, "\tHTTPP: %d   HTTPM: %d   IdentSDIPP: %d   IdentSDIPM: %d\n",
							   asic_acl.ipv6HttpFilter_, asic_acl.ipv6HttpFilterM_,
							   asic_acl.ipv6IdentSrcDstIp_, asic_acl.ipv6IdentSrcDstIpM_);
						/* update acl index */
						acl_start = acl_temp;
					}

				}
				break;
# endif
			default:
				seq_printf(s, "asic_acl.ruleType_(0x%x)\n", asic_acl.ruleType_);

			}

			/* Action type */
			switch (asic_acl.actionType_) {

			case RTL865X_ACL_PERMIT:
			case RTL865X_ACL_REDIRECT_ETHER:
			case RTL865X_ACL_DROP:
			case RTL865X_ACL_TOCPU:
			case RTL865X_ACL_LEGACY_DROP:
			case RTL865X_ACL_DROPCPU_LOG:
			case RTL865X_ACL_MIRROR:
			case RTL865X_ACL_REDIRECT_PPPOE:
			case RTL865X_ACL_MIRROR_KEEP_MATCH:
				seq_printf(s, "\tnetifIdx: %d   pppoeIdx: %d   l2Idx:%d  ", asic_acl.netifIdx_,
					   asic_acl.pppoeIdx_, asic_acl.L2Idx_);
				break;

			case RTL865X_ACL_PRIORITY:
				seq_printf(s, "\tprioirty: %d   ", asic_acl.priority_);
				break;

			case RTL865X_ACL_DEFAULT_REDIRECT:
				seq_printf(s, "\tnextHop:%d  ", asic_acl.nexthopIdx_);
				break;

			case RTL865X_ACL_DROP_RATE_EXCEED_PPS:
			case RTL865X_ACL_LOG_RATE_EXCEED_PPS:
			case RTL865X_ACL_DROP_RATE_EXCEED_BPS:
			case RTL865X_ACL_LOG_RATE_EXCEED_BPS:
				seq_printf(s, "\tratelimitIdx: %d  ", asic_acl.ratelimtIdx_);
				break;
# if defined(CONFIG_RTL_8198C)
			case RTL865X_ACL_VID:
				seq_printf(s, "\taclvid: %d  ", asic_acl.aclvid_);
				break;
# endif
			default:
				;

			}
			seq_printf(s, "pktOpApp: %d\n", asic_acl.pktOpApp_);

		}
#else
		for (; acl_start <= acl_end; acl_start++) {
			if (rtl8651_getAsicAclRule(acl_start, &asic_acl) == FAILED)
				rtlglue_printf("=============%s(%d): get asic acl rule error!\n", __FUNCTION__, __LINE__);

			switch (asic_acl.ruleType_) {
			case RTL8651_ACL_MAC:
				seq_printf(s, " [%d] rule type: %s   rule action: %s\n", acl_start, "Ethernet",
					   actionT[asic_acl.actionType_]);
				seq_printf(s, "\tether type: %x   ether type mask: %x\n", asic_acl.typeLen_,
					   asic_acl.typeLenMask_);
				seq_printf(s, "\tDMAC: %pM  DMACM: %pM\n",
					   asic_acl.dstMac_.octet, asic_acl.dstMacMask_.octet);

				seq_printf(s, "\tSMAC: %pM  SMACM: %pM\n",
					   asic_acl.srcMac_.octet, asic_acl.srcMacMask_.octet);
				break;

			case RTL8651_ACL_IP:
				seq_printf(s, " [%d] rule type: %s   rule action: %s\n", acl_start, "IP",
					   actionT[asic_acl.actionType_]);
				seq_printf(s, "\tdip: %pI4 dipM: %pI4\n", &asic_acl.dstIpAddr_,
					   &asic_acl.dstIpAddrMask_);
				seq_printf(s, "\tsip: %pI4 sipM: %pI4\n", &asic_acl.srcIpAddr_,
					   &asic_acl.srcIpAddrMask_);
				seq_printf(s, "\tTos: %x   TosM: %x   ipProto: %x   ipProtoM: %x   ipFlag: %x   ipFlagM: %x\n",
					   asic_acl.tos_, asic_acl.tosMask_, asic_acl.ipProto_, asic_acl.ipProtoMask_,
					   asic_acl.ipFlag_, asic_acl.ipFlagMask_);

				seq_printf(s, "\t<FOP:%x> <FOM:%x> <http:%x> <httpM:%x> <IdentSdip:%x> <IdentSdipM:%x> \n",
					   asic_acl.ipFOP_, asic_acl.ipFOM_, asic_acl.ipHttpFilter_, asic_acl.ipHttpFilterM_,
					   asic_acl.ipIdentSrcDstIp_, asic_acl.ipIdentSrcDstIpM_);
				seq_printf(s, "\t<DF:%x> <MF:%x>\n", asic_acl.ipDF_, asic_acl.ipMF_);
				break;

			case RTL8652_ACL_IP_RANGE:
				seq_printf(s, " [%d] rule type: %s   rule action: %s\n", acl_start, "IP Range",
					   actionT[asic_acl.actionType_]);
				seq_printf(s, "\tdipU: %pI4 dipL: %pI4\n", &asic_acl.dstIpAddr_,
					   &asic_acl.dstIpAddrMask_);
				seq_printf(s, "\tsipU: %pI4 sipL: %pI4\n", &asic_acl.srcIpAddr_,
					   &asic_acl.srcIpAddrMask_);
				seq_printf(s, "\tTos: %x   TosM: %x   ipProto: %x   ipProtoM: %x   ipFlag: %x   ipFlagM: %x\n",
					   asic_acl.tos_, asic_acl.tosMask_, asic_acl.ipProto_, asic_acl.ipProtoMask_,
					   asic_acl.ipFlag_, asic_acl.ipFlagMask_);
				seq_printf(s, "\t<FOP:%x> <FOM:%x> <http:%x> <httpM:%x> <IdentSdip:%x> <IdentSdipM:%x> \n",
					   asic_acl.ipFOP_, asic_acl.ipFOM_, asic_acl.ipHttpFilter_, asic_acl.ipHttpFilterM_,
					   asic_acl.ipIdentSrcDstIp_, asic_acl.ipIdentSrcDstIpM_);
				seq_printf(s, "\t<DF:%x> <MF:%x>\n", asic_acl.ipDF_, asic_acl.ipMF_);
				break;
			case RTL8651_ACL_ICMP:
				seq_printf(s, " [%d] rule type: %s   rule action: %s\n", acl_start, "ICMP",
					   actionT[asic_acl.actionType_]);
				seq_printf(s, "\tdip: %pI4 dipM: %pI4\n", &asic_acl.dstIpAddr_,
					   &asic_acl.dstIpAddrMask_);
				seq_printf(s, "\tsip: %pI4 sipM: %pI4\n", &asic_acl.srcIpAddr_,
					   &asic_acl.srcIpAddrMask_);
				seq_printf(s, "\tTos: %x   TosM: %x   type: %x   typeM: %x   code: %x   codeM: %x\n",
					   asic_acl.tos_, asic_acl.tosMask_, asic_acl.icmpType_, asic_acl.icmpTypeMask_,
					   asic_acl.icmpCode_, asic_acl.icmpCodeMask_);
				break;
			case RTL8652_ACL_ICMP_IPRANGE:
				seq_printf(s, " [%d] rule type: %s   rule action: %s\n", acl_start, "ICMP IP RANGE",
					   actionT[asic_acl.actionType_]);
				seq_printf(s, "\tdipU: %pI4 dipL: %pI4\n", &asic_acl.dstIpAddr_,
					   &asic_acl.dstIpAddrMask_);
				seq_printf(s, "\tsipU: %pI4 sipL: %pI4\n", &asic_acl.srcIpAddr_,
					   &asic_acl.srcIpAddrMask_);
				seq_printf(s, "\tTos: %x   TosM: %x   type: %x   typeM: %x   code: %x   codeM: %x\n",
					   asic_acl.tos_, asic_acl.tosMask_, asic_acl.icmpType_, asic_acl.icmpTypeMask_,
					   asic_acl.icmpCode_, asic_acl.icmpCodeMask_);
				break;
			case RTL8651_ACL_IGMP:
				seq_printf(s, " [%d] rule type: %s   rule action: %s\n", acl_start, "IGMP",
					   actionT[asic_acl.actionType_]);
				seq_printf(s, "\tdip: %pI4 dipM: %pI4\n", &asic_acl.dstIpAddr_,
					   &asic_acl.dstIpAddrMask_);
				seq_printf(s, "\tsip: %pI4 sipM: %pI4\n", &asic_acl.srcIpAddr_,
					   &asic_acl.srcIpAddrMask_);
				seq_printf(s, "\tTos: %x   TosM: %x   type: %x   typeM: %x\n", asic_acl.tos_, asic_acl.tosMask_,
					   asic_acl.igmpType_, asic_acl.igmpTypeMask_);
				break;

			case RTL8652_ACL_IGMP_IPRANGE:
				seq_printf(s, " [%d] rule type: %s   rule action: %s\n", acl_start, "IGMP IP RANGE",
					   actionT[asic_acl.actionType_]);
				seq_printf(s, "\tdip: %pI4 dipM: %pI4\n", &asic_acl.dstIpAddr_,
					   &asic_acl.dstIpAddrMask_);
				seq_printf(s, "\tsip: %pI4 sipM: %pI4\n", &asic_acl.srcIpAddr_,
					   &asic_acl.srcIpAddrMask_);
				seq_printf(s, "\tTos: %x   TosM: %x   type: %x   typeM: %x\n", asic_acl.tos_, asic_acl.tosMask_,
					   asic_acl.igmpType_, asic_acl.igmpTypeMask_);
				break;

			case RTL8651_ACL_TCP:
				seq_printf(s, " [%d] rule type: %s   rule action: %s\n", acl_start, "TCP",
					   actionT[asic_acl.actionType_]);
				seq_printf(s, "\tdip: %pI4 dipM: %pI4\n", &asic_acl.dstIpAddr_,
					   &asic_acl.dstIpAddrMask_);
				seq_printf(s, "\tsip: %pI4 sipM: %pI4\n", &asic_acl.srcIpAddr_,
					   &asic_acl.srcIpAddrMask_);
				seq_printf(s, "\tTos:%x  TosM:%x  sportL:%d  sportU:%d  dportL:%d  dportU:%d\n",
					   asic_acl.tos_, asic_acl.tosMask_, asic_acl.tcpSrcPortLB_, asic_acl.tcpSrcPortUB_,
					   asic_acl.tcpDstPortLB_, asic_acl.tcpDstPortUB_);
				seq_printf(s, "\tflag: %x  flagM: %x  <URG:%x> <ACK:%x> <PSH:%x> <RST:%x> <SYN:%x> <FIN:%x>\n",
					   asic_acl.tcpFlag_, asic_acl.tcpFlagMask_, asic_acl.tcpURG_, asic_acl.tcpACK_,
					   asic_acl.tcpPSH_, asic_acl.tcpRST_, asic_acl.tcpSYN_, asic_acl.tcpFIN_);
				break;
			case RTL8652_ACL_TCP_IPRANGE:
				seq_printf(s, " [%d] rule type: %s   rule action: %s\n", acl_start, "TCP IP RANGE",
					   actionT[asic_acl.actionType_]);
				seq_printf(s, "\tdipU: %pI4 dipL: %pI4\n", &asic_acl.dstIpAddr_,
					   &asic_acl.dstIpAddrMask_);
				seq_printf(s, "\tsipU: %pI4 sipL: %pI4\n", &asic_acl.srcIpAddr_,
					   &asic_acl.srcIpAddrMask_);
				seq_printf(s, "\tTos:%x  TosM:%x  sportL:%d  sportU:%d  dportL:%d  dportU:%d\n",
					   asic_acl.tos_, asic_acl.tosMask_, asic_acl.tcpSrcPortLB_, asic_acl.tcpSrcPortUB_,
					   asic_acl.tcpDstPortLB_, asic_acl.tcpDstPortUB_);
				seq_printf(s, "\tflag: %x  flagM: %x  <URG:%x> <ACK:%x> <PSH:%x> <RST:%x> <SYN:%x> <FIN:%x>\n",
					   asic_acl.tcpFlag_, asic_acl.tcpFlagMask_, asic_acl.tcpURG_, asic_acl.tcpACK_,
					   asic_acl.tcpPSH_, asic_acl.tcpRST_, asic_acl.tcpSYN_, asic_acl.tcpFIN_);
				break;

			case RTL8651_ACL_UDP:
				seq_printf(s, " [%d] rule type: %s   rule action: %s\n", acl_start, "UDP",
					   actionT[asic_acl.actionType_]);
				seq_printf(s, "\tdip: %pI4 dipM: %pI4\n", &asic_acl.dstIpAddr_,
					   &asic_acl.dstIpAddrMask_);
				seq_printf(s, "\tsip: %pI4 sipM: %pI4\n", &asic_acl.srcIpAddr_,
					   &asic_acl.srcIpAddrMask_);
				seq_printf(s, "\tTos:%x  TosM:%x  sportL:%d  sportU:%d  dportL:%d  dportU:%d\n",
					   asic_acl.tos_, asic_acl.tosMask_, asic_acl.udpSrcPortLB_, asic_acl.udpSrcPortUB_,
					   asic_acl.udpDstPortLB_, asic_acl.udpDstPortUB_);
				break;
			case RTL8652_ACL_UDP_IPRANGE:
				seq_printf(s, " [%d] rule type: %s   rule action: %s\n", acl_start, "UDP IP RANGE",
					   actionT[asic_acl.actionType_]);
				seq_printf(s, "\tdipU: %pI4 dipL: %pI4\n", &asic_acl.dstIpAddr_,
					   &asic_acl.dstIpAddrMask_);
				seq_printf(s, "\tsipU: %pI4 sipL: %pI4\n", &asic_acl.srcIpAddr_,
					   &asic_acl.srcIpAddrMask_);
				seq_printf(s, "\tTos:%x  TosM:%x  sportL:%d  sportU:%d  dportL:%d  dportU:%d\n",
					   asic_acl.tos_, asic_acl.tosMask_, asic_acl.udpSrcPortLB_, asic_acl.udpSrcPortUB_,
					   asic_acl.udpDstPortLB_, asic_acl.udpDstPortUB_);
				break;

			case RTL8651_ACL_IFSEL:
				seq_printf(s, " [%d] rule type: %s   rule action: %s\n", acl_start, "UDP",
					   actionT[asic_acl.actionType_]);
				seq_printf(s, "\tgidxSel: %x\n", asic_acl.gidxSel_);
				break;
			case RTL8651_ACL_SRCFILTER:
				seq_printf(s, " [%d] rule type: %s   rule action: %s\n", acl_start, "Source Filter",
					   actionT[asic_acl.actionType_]);
				seq_printf(s, "\tSMAC: %pM  SMACM: %pM\n",
					   asic_acl.srcFilterMac_.octet, asic_acl.srcFilterMacMask_.octet);
				seq_printf(s, "\tsvidx: %d   svidxM: %x   sport: %d   sportM: %x   ProtoType: %x\n",
					   asic_acl.srcFilterVlanIdx_, asic_acl.srcFilterVlanIdxMask_, asic_acl.srcFilterPort_,
					   asic_acl.srcFilterPortMask_,
					   (asic_acl.srcFilterIgnoreL3L4_ ==
					    TRUE ? 2 : (asic_acl.srcFilterIgnoreL4_ == 1 ? 1 : 0))
				    );
				seq_printf(s, "\tsip: %pI4   sipM: %pI4\n", &asic_acl.srcFilterIpAddr_,
					   &asic_acl.srcFilterIpAddrMask_);
				seq_printf(s, "\tsportL: %d   sportU: %d\n", asic_acl.srcFilterPortLowerBound_,
					   asic_acl.srcFilterPortUpperBound_);
				break;

			case RTL8652_ACL_SRCFILTER_IPRANGE:
				seq_printf(s, " [%d] rule type: %s   rule action: %s\n", acl_start, "Source Filter(IP RANGE)",
					   actionT[asic_acl.actionType_]);
				seq_printf(s, "\tSMAC: %pM  SMACM: %pM\n",
					   asic_acl.srcFilterMac_.octet, asic_acl.srcFilterMacMask_.octet);
				seq_printf(s, "\tsvidx: %d   svidxM: %x   sport: %d   sportM: %x   ProtoType: %x\n",
					   asic_acl.srcFilterVlanIdx_, asic_acl.srcFilterVlanIdxMask_, asic_acl.srcFilterPort_,
					   asic_acl.srcFilterPortMask_,
					   (asic_acl.srcFilterIgnoreL3L4_ ==
					    TRUE ? 2 : (asic_acl.srcFilterIgnoreL4_ == 1 ? 1 : 0))
				    );
				seq_printf(s, "\tsipU: %pI4   sipL: %pI4\n", &asic_acl.srcFilterIpAddr_,
					   &asic_acl.srcFilterIpAddrMask_);
				seq_printf(s, "\tsportL: %d   sportU: %d\n", asic_acl.srcFilterPortLowerBound_,
					   asic_acl.srcFilterPortUpperBound_);
				break;

			case RTL8651_ACL_DSTFILTER:
				seq_printf(s, " [%d] rule type: %s   rule action: %s\n", acl_start, "Deatination Filter",
					   actionT[asic_acl.actionType_]);
				seq_printf(s, "\tDMAC: %pM  DMACM: %pM\n",
					   asic_acl.dstFilterMac_.octet, asic_acl.dstFilterMacMask_.octet);
				seq_printf(s, "\tdvidx: %d   dvidxM: %x  ProtoType: %x   dportL: %d   dportU: %d\n",
					   asic_acl.dstFilterVlanIdx_, asic_acl.dstFilterVlanIdxMask_,
					   (asic_acl.dstFilterIgnoreL3L4_ ==
					    TRUE ? 2 : (asic_acl.dstFilterIgnoreL4_ == 1 ? 1 : 0)),
					   asic_acl.dstFilterPortLowerBound_, asic_acl.dstFilterPortUpperBound_);
				seq_printf(s, "\tdip: %pI4   dipM: %pI4\n", &asic_acl.dstFilterIpAddr_,
					   &asic_acl.dstFilterIpAddrMask_);
				break;
			case RTL8652_ACL_DSTFILTER_IPRANGE:
				seq_printf(s, " [%d] rule type: %s   rule action: %s\n", acl_start,
					   "Deatination Filter(IP Range)", actionT[asic_acl.actionType_]);
				seq_printf(s, "\tDMAC: %pM  DMACM: %pM\n",
					   asic_acl.dstFilterMac_.octet, asic_acl.dstFilterMacMask_.octet);
				seq_printf(s, "\tdvidx: %d   dvidxM: %x  ProtoType: %x   dportL: %d   dportU: %d\n",
					   asic_acl.dstFilterVlanIdx_, asic_acl.dstFilterVlanIdxMask_,
					   (asic_acl.dstFilterIgnoreL3L4_ ==
					    TRUE ? 2 : (asic_acl.dstFilterIgnoreL4_ == 1 ? 1 : 0)),
					   asic_acl.dstFilterPortLowerBound_, asic_acl.dstFilterPortUpperBound_);
				seq_printf(s, "\tdipU: %pI4   dipL: %pI4\n", &asic_acl.dstFilterIpAddr_,
					   &asic_acl.dstFilterIpAddrMask_);
				break;

			default:
				seq_printf(s, "asic_acl.ruleType_(0x%x)\n", asic_acl.ruleType_);

			}

			/* Action type */
			switch (asic_acl.actionType_) {

			case RTL8651_ACL_PERMIT:	/* 0x00 */
			case RTL8651_ACL_REDIRECT:	/* 0x01 */
			case RTL8651_ACL_CPU:	/* 0x03 */
			case RTL8651_ACL_DROP:	/* 0x02, 0x04 */
			case RTL8651_ACL_DROP_LOG:	/* 0x05 */
			case RTL8651_ACL_MIRROR:	/* 0x06 */
			case RTL8651_ACL_REDIRECT_PPPOE:	/* 0x07 */
			case RTL8651_ACL_MIRROR_KEEP_MATCH:	/* 0x09 */
				seq_printf(s, "\tdvidx: %d   hp: %d   pppoeIdx: %d   nxtHop:%d  ", asic_acl.dvid_,
					   asic_acl.priority_, asic_acl.pppoeIdx_, asic_acl.nextHop_);
				break;

			case RTL8651_ACL_POLICY:	/* 0x08 */
				seq_printf(s, "\thp: %d   nxtHopIdx: %d  ", asic_acl.priority_, asic_acl.nhIndex);
				break;

			case RTL8651_ACL_PRIORITY:	/* 0x08 */
				seq_printf(s, "\tprioirty: %d   ", asic_acl.priority);
				break;

			case RTL8651_ACL_DROP_RATE_EXCEED_PPS:	/* 0x0a */
			case RTL8651_ACL_LOG_RATE_EXCEED_PPS:	/* 0x0b */
			case RTL8651_ACL_DROP_RATE_EXCEED_BPS:	/* 0x0c */
			case RTL8651_ACL_LOG_RATE_EXCEED_BPS:	/* 0x0d */
				seq_printf(s, "\trlIdx: %d  ", asic_acl.rlIndex);
				break;
			default:
				;

			}
			seq_printf(s, "pktOpApp: %d\n", asic_acl.pktOpApp);

		}

#endif

		if (outRule == FALSE) {
			acl_start = asic_intf.outAclStart;
			acl_end = asic_intf.outAclEnd;
			outRule = TRUE;
			goto again;
		}
	}

#if defined(CONFIG_RTL_LOCAL_PUBLIC) || defined(CONFIG_RTL_MULTIPLE_WAN) || defined(CONFIG_RTL_HW_VLAN_SUPPORT)
	{

		outRule = FALSE;
		rtl865x_getDefACLForNetDecisionMiss(&defInAclStart, &defInAclEnd, &defOutAclStart, &defOutAclEnd);
		acl_start = defInAclStart;
		acl_end = defInAclEnd;
		seq_printf(s, "\nacl_start(%d), acl_end(%d)", acl_start, acl_end);
 again_forOutAcl:
		if (outRule == FALSE)
			seq_printf(s, "\n<<Default Ingress Rule for Netif Missed>>:\n");
		else
			seq_printf(s, "\n<<Default Egress Rule for Netif Missed>>:\n");

		for (; acl_start <= acl_end; acl_start++) {
			if (_rtl865x_getAclFromAsic(acl_start, &asic_acl) == FAILED)
				seq_printf(s, "Failed to get %d entry(%d).\n", acl_start, __LINE__);

			switch (asic_acl.ruleType_) {
			case RTL865X_ACL_MAC:
				seq_printf(s, " [%d] rule type: %s   rule action: %s\n", acl_start, "Ethernet",
					   actionT[asic_acl.actionType_]);
				seq_printf(s, "\tether type: %x   ether type mask: %x\n", asic_acl.typeLen_,
					   asic_acl.typeLenMask_);
				seq_printf(s, "\tDMAC: %pM  DMACM: %pM\n",
					   asic_acl.dstMac_.octet, asic_acl.dstMacMask_.octet);

				seq_printf(s, "\tSMAC: %pM  SMACM: %pM\n",
					   asic_acl.srcMac_.octet, asic_acl.srcMacMask_.octet);
				break;

			case RTL865X_ACL_IP:
				seq_printf(s, " [%d] rule type: %s   rule action: %s\n", acl_start, "IP",
					   actionT[asic_acl.actionType_]);
				seq_printf(s, "\tdip: %pI4 dipM: %pI4\n", &asic_acl.dstIpAddr_,
					   &asic_acl.dstIpAddrMask_);
				seq_printf(s, "\tsip: %pI4 sipM: %pI4\n", &asic_acl.srcIpAddr_,
					   &asic_acl.srcIpAddrMask_);
				seq_printf(s, "\tTos: %x   TosM: %x   ipProto: %x   ipProtoM: %x   ipFlag: %x   ipFlagM: %x\n",
					   asic_acl.tos_, asic_acl.tosMask_, asic_acl.ipProto_, asic_acl.ipProtoMask_,
					   asic_acl.ipFlag_, asic_acl.ipFlagMask_);

				seq_printf(s, "\t<FOP:%x> <FOM:%x> <http:%x> <httpM:%x> <IdentSdip:%x> <IdentSdipM:%x> \n",
					   asic_acl.ipFOP_, asic_acl.ipFOM_, asic_acl.ipHttpFilter_, asic_acl.ipHttpFilterM_,
					   asic_acl.ipIdentSrcDstIp_, asic_acl.ipIdentSrcDstIpM_);
				seq_printf(s, "\t<DF:%x> <MF:%x>\n", asic_acl.ipDF_, asic_acl.ipMF_);
				break;

			case RTL865X_ACL_IP_RANGE:
				seq_printf(s, " [%d] rule type: %s   rule action: %s\n", acl_start, "IP Range",
					   actionT[asic_acl.actionType_]);
				seq_printf(s, "\tdipU: %pI4 dipL: %pI4\n", &asic_acl.dstIpAddr_,
					   &asic_acl.dstIpAddrMask_);
				seq_printf(s, "\tsipU: %pI4 sipL: %pI4\n", &asic_acl.srcIpAddr_,
					   &asic_acl.srcIpAddrMask_);
				seq_printf(s, "\tTos: %x   TosM: %x   ipProto: %x   ipProtoM: %x   ipFlag: %x   ipFlagM: %x\n",
					   asic_acl.tos_, asic_acl.tosMask_, asic_acl.ipProto_, asic_acl.ipProtoMask_,
					   asic_acl.ipFlag_, asic_acl.ipFlagMask_);
				seq_printf(s, "\t<FOP:%x> <FOM:%x> <http:%x> <httpM:%x> <IdentSdip:%x> <IdentSdipM:%x> \n",
					   asic_acl.ipFOP_, asic_acl.ipFOM_, asic_acl.ipHttpFilter_, asic_acl.ipHttpFilterM_,
					   asic_acl.ipIdentSrcDstIp_, asic_acl.ipIdentSrcDstIpM_);
				seq_printf(s, "\t<DF:%x> <MF:%x>\n", asic_acl.ipDF_, asic_acl.ipMF_);
				break;
			case RTL865X_ACL_ICMP:
				seq_printf(s, " [%d] rule type: %s   rule action: %s\n", acl_start, "ICMP",
					   actionT[asic_acl.actionType_]);
				seq_printf(s, "\tdip: %pI4 dipM: %pI4\n", &asic_acl.dstIpAddr_,
					   &asic_acl.dstIpAddrMask_);
				seq_printf(s, "\tsip: %pI4 sipM: %pI4\n", &asic_acl.srcIpAddr_,
					   &asic_acl.srcIpAddrMask_);
				seq_printf(s, "\tTos: %x   TosM: %x   type: %x   typeM: %x   code: %x   codeM: %x\n",
					   asic_acl.tos_, asic_acl.tosMask_, asic_acl.icmpType_, asic_acl.icmpTypeMask_,
					   asic_acl.icmpCode_, asic_acl.icmpCodeMask_);
				break;
			case RTL865X_ACL_ICMP_IPRANGE:
				seq_printf(s, " [%d] rule type: %s   rule action: %s\n", acl_start, "ICMP IP RANGE",
					   actionT[asic_acl.actionType_]);
				seq_printf(s, "\tdipU: %pI4 dipL: %pI4\n", &asic_acl.dstIpAddr_,
					   &asic_acl.dstIpAddrMask_);
				seq_printf(s, "\tsipU: %pI4 sipL: %pI4\n", &asic_acl.srcIpAddr_,
					   &asic_acl.srcIpAddrMask_);
				seq_printf(s, "\tTos: %x   TosM: %x   type: %x   typeM: %x   code: %x   codeM: %x\n",
					   asic_acl.tos_, asic_acl.tosMask_, asic_acl.icmpType_, asic_acl.icmpTypeMask_,
					   asic_acl.icmpCode_, asic_acl.icmpCodeMask_);
				break;
			case RTL865X_ACL_IGMP:
				seq_printf(s, " [%d] rule type: %s   rule action: %s\n", acl_start, "IGMP",
					   actionT[asic_acl.actionType_]);
				seq_printf(s, "\tdip: %pI4 dipM: %pI4\n", &asic_acl.dstIpAddr_,
					   &asic_acl.dstIpAddrMask_);
				seq_printf(s, "\tsip: %pI4 sipM: %pI4\n", &asic_acl.srcIpAddr_,
					   &asic_acl.srcIpAddrMask_);
				seq_printf(s, "\tTos: %x   TosM: %x   type: %x   typeM: %x\n", asic_acl.tos_, asic_acl.tosMask_,
					   asic_acl.igmpType_, asic_acl.igmpTypeMask_);
				break;

			case RTL865X_ACL_IGMP_IPRANGE:
				seq_printf(s, " [%d] rule type: %s   rule action: %s\n", acl_start, "IGMP IP RANGE",
					   actionT[asic_acl.actionType_]);
				seq_printf(s, "\tdip: %pI4 dipM: %pI4\n", &asic_acl.dstIpAddr_,
					   &asic_acl.dstIpAddrMask_);
				seq_printf(s, "\tsip: %pI4 sipM: %pI4\n", &asic_acl.srcIpAddr_,
					   &asic_acl.srcIpAddrMask_);
				seq_printf(s, "\tTos: %x   TosM: %x   type: %x   typeM: %x\n", asic_acl.tos_, asic_acl.tosMask_,
					   asic_acl.igmpType_, asic_acl.igmpTypeMask_);
				break;

			case RTL865X_ACL_TCP:
				seq_printf(s, " [%d] rule type: %s   rule action: %s\n", acl_start, "TCP",
					   actionT[asic_acl.actionType_]);
				seq_printf(s, "\tdip: %pI4 dipM: %pI4\n", &asic_acl.dstIpAddr_,
					   &asic_acl.dstIpAddrMask_);
				seq_printf(s, "\tsip: %pI4 sipM: %pI4\n", &asic_acl.srcIpAddr_,
					   &asic_acl.srcIpAddrMask_);
				seq_printf(s, "\tTos:%x  TosM:%x  sportL:%d  sportU:%d  dportL:%d  dportU:%d\n",
					   asic_acl.tos_, asic_acl.tosMask_, asic_acl.tcpSrcPortLB_, asic_acl.tcpSrcPortUB_,
					   asic_acl.tcpDstPortLB_, asic_acl.tcpDstPortUB_);
				seq_printf(s, "\tflag: %x  flagM: %x  <URG:%x> <ACK:%x> <PSH:%x> <RST:%x> <SYN:%x> <FIN:%x>\n",
					   asic_acl.tcpFlag_, asic_acl.tcpFlagMask_, asic_acl.tcpURG_, asic_acl.tcpACK_,
					   asic_acl.tcpPSH_, asic_acl.tcpRST_, asic_acl.tcpSYN_, asic_acl.tcpFIN_);
				break;
			case RTL865X_ACL_TCP_IPRANGE:
				seq_printf(s, " [%d] rule type: %s   rule action: %s\n", acl_start, "TCP IP RANGE",
					   actionT[asic_acl.actionType_]);
				seq_printf(s, "\tdipU: %pI4 dipL: %pI4\n", &asic_acl.dstIpAddr_,
					   &asic_acl.dstIpAddrMask_);
				seq_printf(s, "\tsipU: %pI4 sipL: %pI4\n", &asic_acl.srcIpAddr_,
					   &asic_acl.srcIpAddrMask_);
				seq_printf(s, "\tTos:%x  TosM:%x  sportL:%d  sportU:%d  dportL:%d  dportU:%d\n",
					   asic_acl.tos_, asic_acl.tosMask_, asic_acl.tcpSrcPortLB_, asic_acl.tcpSrcPortUB_,
					   asic_acl.tcpDstPortLB_, asic_acl.tcpDstPortUB_);
				seq_printf(s, "\tflag: %x  flagM: %x  <URG:%x> <ACK:%x> <PSH:%x> <RST:%x> <SYN:%x> <FIN:%x>\n",
					   asic_acl.tcpFlag_, asic_acl.tcpFlagMask_, asic_acl.tcpURG_, asic_acl.tcpACK_,
					   asic_acl.tcpPSH_, asic_acl.tcpRST_, asic_acl.tcpSYN_, asic_acl.tcpFIN_);
				break;

			case RTL865X_ACL_UDP:
				seq_printf(s, " [%d] rule type: %s   rule action: %s\n", acl_start, "UDP",
					   actionT[asic_acl.actionType_]);
				seq_printf(s, "\tdip: %pI4 dipM: %pI4\n", &asic_acl.dstIpAddr_,
					   &asic_acl.dstIpAddrMask_);
				seq_printf(s, "\tsip: %pI4 sipM: %pI4\n", &asic_acl.srcIpAddr_,
					   &asic_acl.srcIpAddrMask_);
				seq_printf(s, "\tTos:%x  TosM:%x  sportL:%d  sportU:%d  dportL:%d  dportU:%d\n",
					   asic_acl.tos_, asic_acl.tosMask_, asic_acl.udpSrcPortLB_, asic_acl.udpSrcPortUB_,
					   asic_acl.udpDstPortLB_, asic_acl.udpDstPortUB_);
				break;
			case RTL865X_ACL_UDP_IPRANGE:
				seq_printf(s, " [%d] rule type: %s   rule action: %s\n", acl_start, "UDP IP RANGE",
					   actionT[asic_acl.actionType_]);
				seq_printf(s, "\tdipU: %pI4 dipL: %pI4\n", &asic_acl.dstIpAddr_,
					   &asic_acl.dstIpAddrMask_);
				seq_printf(s, "\tsipU: %pI4 sipL: %pI4\n", &asic_acl.srcIpAddr_,
					   &asic_acl.srcIpAddrMask_);
				seq_printf(s, "\tTos:%x  TosM:%x  sportL:%d  sportU:%d  dportL:%d  dportU:%d\n",
					   asic_acl.tos_, asic_acl.tosMask_, asic_acl.udpSrcPortLB_, asic_acl.udpSrcPortUB_,
					   asic_acl.udpDstPortLB_, asic_acl.udpDstPortUB_);
				break;

			case RTL865X_ACL_SRCFILTER:
				seq_printf(s, " [%d] rule type: %s   rule action: %s\n", acl_start, "Source Filter",
					   actionT[asic_acl.actionType_]);
				seq_printf(s, "\tSMAC: %pM  SMACM: %pM\n",
					   asic_acl.srcFilterMac_.octet, asic_acl.srcFilterMacMask_.octet);
				seq_printf(s, "\tsvidx: %d   svidxM: %x   sport: %d   sportM: %x   ProtoType: %x\n",
					   asic_acl.srcFilterVlanIdx_, asic_acl.srcFilterVlanIdxMask_, asic_acl.srcFilterPort_,
					   asic_acl.srcFilterPortMask_,
					   (asic_acl.srcFilterIgnoreL3L4_ ==
					    TRUE ? 2 : (asic_acl.srcFilterIgnoreL4_ == 1 ? 1 : 0))
				    );
				seq_printf(s, "\tsip: %pI4   sipM: %pI4\n", &asic_acl.srcFilterIpAddr_,
					   &asic_acl.srcFilterIpAddrMask_);
				seq_printf(s, "\tsportL: %d   sportU: %d\n", asic_acl.srcFilterPortLowerBound_,
					   asic_acl.srcFilterPortUpperBound_);
				break;

			case RTL865X_ACL_SRCFILTER_IPRANGE:
				seq_printf(s, " [%d] rule type: %s   rule action: %s\n", acl_start, "Source Filter(IP RANGE)",
					   actionT[asic_acl.actionType_]);
				seq_printf(s, "\tSMAC: %pM  SMACM: %pM\n",
					   asic_acl.srcFilterMac_.octet, asic_acl.srcFilterMacMask_.octet);
				seq_printf(s, "\tsvidx: %d   svidxM: %x   sport: %d   sportM: %x   ProtoType: %x\n",
					   asic_acl.srcFilterVlanIdx_, asic_acl.srcFilterVlanIdxMask_, asic_acl.srcFilterPort_,
					   asic_acl.srcFilterPortMask_,
					   (asic_acl.srcFilterIgnoreL3L4_ ==
					    TRUE ? 2 : (asic_acl.srcFilterIgnoreL4_ == 1 ? 1 : 0))
				    );
				seq_printf(s, "\tsipU: %pI4   sipL: %pI4\n", &asic_acl.srcFilterIpAddr_,
					   &asic_acl.srcFilterIpAddrMask_);
				seq_printf(s, "\tsportL: %d   sportU: %d\n", asic_acl.srcFilterPortLowerBound_,
					   asic_acl.srcFilterPortUpperBound_);
				break;

			case RTL865X_ACL_DSTFILTER:
				seq_printf(s, " [%d] rule type: %s   rule action: %s\n", acl_start, "Deatination Filter",
					   actionT[asic_acl.actionType_]);
				seq_printf(s, "\tDMAC: %pM  DMACM: %pM\n",
					   asic_acl.dstFilterMac_.octet, asic_acl.dstFilterMacMask_.octet);
				seq_printf(s, "\tdvidx: %d   dvidxM: %x  ProtoType: %x   dportL: %d   dportU: %d\n",
					   asic_acl.dstFilterVlanIdx_, asic_acl.dstFilterVlanIdxMask_,
					   (asic_acl.dstFilterIgnoreL3L4_ ==
					    TRUE ? 2 : (asic_acl.dstFilterIgnoreL4_ == 1 ? 1 : 0)),
					   asic_acl.dstFilterPortLowerBound_, asic_acl.dstFilterPortUpperBound_);
				seq_printf(s, "\tdip: %pI4   dipM: %pI4\n", &asic_acl.dstFilterIpAddr_,
					   &asic_acl.dstFilterIpAddrMask_);
				break;
			case RTL865X_ACL_DSTFILTER_IPRANGE:
				seq_printf(s, " [%d] rule type: %s   rule action: %s\n", acl_start,
					   "Deatination Filter(IP Range)", actionT[asic_acl.actionType_]);
				seq_printf(s, "\tDMAC: %pM  DMACM: %pM\n",
					   asic_acl.dstFilterMac_.octet, asic_acl.dstFilterMacMask_.octet);
				seq_printf(s, "\tdvidx: %d   dvidxM: %x  ProtoType: %x   dportL: %d   dportU: %d\n",
					   asic_acl.dstFilterVlanIdx_, asic_acl.dstFilterVlanIdxMask_,
					   (asic_acl.dstFilterIgnoreL3L4_ ==
					    TRUE ? 2 : (asic_acl.dstFilterIgnoreL4_ == 1 ? 1 : 0)),
					   asic_acl.dstFilterPortLowerBound_, asic_acl.dstFilterPortUpperBound_);
				seq_printf(s, "\tdipU: %pI4   dipL: %pI4\n", &asic_acl.dstFilterIpAddr_,
					   &asic_acl.dstFilterIpAddrMask_);
				break;

# if defined(CONFIG_RTL_8198C)
			case RTL865X_ACL_IPV6:	/* IP Rule Type: 0x0010 */
			case RTL865X_ACL_IPV6_RANGE:
				/* a ipv6 rule occupied  two entry, function _rtl865x_getAclFromAsic take one entry at a time,
				 * so, need to call function _rtl865x_getAclFromAsic again.
				 */
				//rtl865x_AclRule_t asic_acl2;
				//unsigned int acl_temp = acl_start;
				acl_temp = acl_start;
				acl_temp++;
				if (acl_temp <= acl_end)	//the second entry index of ipv6 rule, should  less than or equal to acl_end.
				{
					memset(&asic_acl2, 0x00, sizeof(rtl865x_AclRule_t));
					if (_rtl865x_getAclFromAsic(acl_temp, &asic_acl2) == FAILED)
						seq_printf(s, "Failed to get %d entry(%d).\n", acl_temp, __LINE__);

					if ((!asic_acl2.ipv6EntryType_) && asic_acl.ipv6EntryType_) {
						asic_acl.dstIpV6Addr_.v6_addr32[3] = asic_acl2.dstIpV6Addr_.v6_addr32[3];
						asic_acl.dstIpV6Addr_.v6_addr32[2] = asic_acl2.dstIpV6Addr_.v6_addr32[2];
						asic_acl.dstIpV6Addr_.v6_addr32[1] = asic_acl2.dstIpV6Addr_.v6_addr32[1];
						asic_acl.dstIpV6Addr_.v6_addr32[0] = asic_acl2.dstIpV6Addr_.v6_addr32[0];

						asic_acl.dstIpV6AddrMask_.v6_addr32[3] =
						    asic_acl2.dstIpV6AddrMask_.v6_addr32[3];
						asic_acl.dstIpV6AddrMask_.v6_addr32[2] =
						    asic_acl2.dstIpV6AddrMask_.v6_addr32[2];
						asic_acl.dstIpV6AddrMask_.v6_addr32[1] =
						    asic_acl2.dstIpV6AddrMask_.v6_addr32[1];
						asic_acl.dstIpV6AddrMask_.v6_addr32[0] =
						    asic_acl2.dstIpV6AddrMask_.v6_addr32[0];

						asic_acl.ipv6TrafficClass_ = asic_acl2.ipv6TrafficClass_;
						asic_acl.ipv6TrafficClassM_ = asic_acl2.ipv6TrafficClassM_;
						asic_acl.ipv6NextHeader_ = asic_acl2.ipv6NextHeader_;
						asic_acl.ipv6NextHeaderM_ = asic_acl2.ipv6NextHeaderM_;
						asic_acl.ipv6HttpFilter_ = asic_acl2.ipv6HttpFilter_;
						asic_acl.ipv6HttpFilterM_ = asic_acl2.ipv6HttpFilterM_;
						asic_acl.ipv6IdentSrcDstIp_ = asic_acl2.ipv6IdentSrcDstIp_;
						asic_acl.ipv6IdentSrcDstIpM_ = asic_acl2.ipv6IdentSrcDstIpM_;
						/* ActionType and ActionField useless in entry0 */
						asic_acl.actionType_ = asic_acl2.actionType_;
						switch (asic_acl.actionType_) {

						case RTL865X_ACL_PERMIT:
						case RTL865X_ACL_REDIRECT_ETHER:
						case RTL865X_ACL_DROP:
						case RTL865X_ACL_TOCPU:
						case RTL865X_ACL_LEGACY_DROP:
						case RTL865X_ACL_DROPCPU_LOG:
						case RTL865X_ACL_MIRROR:
						case RTL865X_ACL_REDIRECT_PPPOE:
						case RTL865X_ACL_MIRROR_KEEP_MATCH:
							asic_acl.L2Idx_ = asic_acl2.L2Idx_;
							asic_acl.netifIdx_ = asic_acl2.netifIdx_;
							asic_acl.pppoeIdx_ = asic_acl2.pppoeIdx_;
							break;

						case RTL865X_ACL_DEFAULT_REDIRECT:
							asic_acl.nexthopIdx_ = asic_acl2.nexthopIdx_;
							break;

						case RTL865X_ACL_DROP_RATE_EXCEED_PPS:
						case RTL865X_ACL_LOG_RATE_EXCEED_PPS:
						case RTL865X_ACL_DROP_RATE_EXCEED_BPS:
						case RTL865X_ACL_LOG_RATE_EXCEED_BPS:
							asic_acl.ratelimtIdx_ = asic_acl2.ratelimtIdx_;
							break;
						case RTL865X_ACL_PRIORITY:
							asic_acl.priority_ = asic_acl2.priority_;
							break;
						case RTL865X_ACL_VID:
							asic_acl.aclvid_ = asic_acl2.aclvid_;
							break;
						}
						/* INV useless in entry 0 */
						asic_acl.ipv6Invert_ = asic_acl2.ipv6Invert_;
						//asic_acl.ipv6Combine_  = asic_acl2.ipv6Combine_ ;
						//asic_acl.ipv6IPtunnel_ = asic_acl2.ipv6IPtunnel_;
						seq_printf(s, " [%d-%d] rule type: %s   rule action: %s\n", acl_start, acl_temp,
							   "IPv6", actionT[asic_acl.actionType_]);
						if (RTL865X_ACL_IPV6 == asic_acl.ruleType_) {
							seq_printf(s, "\tsip: %pI6c  sipM: %pI6c\n",
								   asic_acl.srcIpV6Addr_.v6_addr16, asic_acl.srcIpV6AddrMask_.v6_addr16);
							seq_printf(s, "\tdip: %pI6c  dipM: %pI6c\n",
								   asic_acl.dstIpV6Addr_.v6_addr16, asic_acl.dstIpV6AddrMask_.v6_addr16);

						} else if (RTL865X_ACL_IPV6_RANGE == asic_acl.ruleType_) {
							seq_printf(s, "\tsipLB: %pI6c  sipUB: %pI6c\n",
								   asic_acl.srcIpV6AddrLB_.v6_addr16, asic_acl.srcIpV6AddrUB_.v6_addr16);
							seq_printf(s, "\tdipLB: %pI6c  dipUB: %pI6c\n",
								   asic_acl.dstIpV6AddrLB_.v6_addr16, asic_acl.dstIpV6AddrUB_.v6_addr16);
						}
						seq_printf(s, "\tFlowLabel: 0x%x   FlowLabelM: 0x%x\n",
							   asic_acl.ipv6FlowLabel_, asic_acl.ipv6FlowLabelM_);
						seq_printf(s, "\tInvert: %d   Combine: %d   IPtunnel: %d\n",
							   asic_acl.ipv6Invert_, asic_acl.ipv6Combine_, asic_acl.ipv6IPtunnel_);
						seq_printf(s,
							   "\tTrafficClassP: %d   TrafficClassM: %d   NextHeaderP: %d   NextHeaderM: %d\n",
							   asic_acl.ipv6TrafficClass_, asic_acl.ipv6TrafficClassM_,
							   asic_acl.ipv6NextHeader_, asic_acl.ipv6NextHeaderM_);
						seq_printf(s, "\tHTTPP: %d   HTTPM: %d   IdentSDIPP: %d   IdentSDIPM: %d\n",
							   asic_acl.ipv6HttpFilter_, asic_acl.ipv6HttpFilterM_,
							   asic_acl.ipv6IdentSrcDstIp_, asic_acl.ipv6IdentSrcDstIpM_);
						/* update acl index */
						acl_start = acl_temp;
					}

				}
				break;
# endif
			default:
				seq_printf(s, "asic_acl.ruleType_(0x%x)\n", asic_acl.ruleType_);
			}

			/* Action type */
			switch (asic_acl.actionType_) {
			case RTL865X_ACL_PERMIT:
			case RTL865X_ACL_REDIRECT_ETHER:
			case RTL865X_ACL_DROP:
			case RTL865X_ACL_TOCPU:
			case RTL865X_ACL_LEGACY_DROP:
			case RTL865X_ACL_DROPCPU_LOG:
			case RTL865X_ACL_MIRROR:
			case RTL865X_ACL_REDIRECT_PPPOE:
			case RTL865X_ACL_MIRROR_KEEP_MATCH:
				seq_printf(s, "\tnetifIdx: %d   pppoeIdx: %d   l2Idx:%d  ", asic_acl.netifIdx_,
					   asic_acl.pppoeIdx_, asic_acl.L2Idx_);
				break;
			case RTL865X_ACL_PRIORITY:
				seq_printf(s, "\tprioirty: %d   ", asic_acl.priority_);
				break;
			case RTL865X_ACL_DEFAULT_REDIRECT:
				seq_printf(s, "\tnextHop:%d  ", asic_acl.nexthopIdx_);
				break;
			case RTL865X_ACL_DROP_RATE_EXCEED_PPS:
			case RTL865X_ACL_LOG_RATE_EXCEED_PPS:
			case RTL865X_ACL_DROP_RATE_EXCEED_BPS:
			case RTL865X_ACL_LOG_RATE_EXCEED_BPS:
				seq_printf(s, "\tratelimitIdx: %d  ", asic_acl.ratelimtIdx_);
				break;
# if defined(CONFIG_RTL_8198C)
			case RTL865X_ACL_VID:
				seq_printf(s, "\taclvid: %d  ", asic_acl.aclvid_);
				break;
# endif
			default:
				break;
			}
			seq_printf(s, "pktOpApp: %d\n", asic_acl.pktOpApp_);

		}

		if (outRule == FALSE) {
			acl_start = defOutAclStart;
			acl_end = defOutAclEnd;
			outRule = TRUE;
			goto again_forOutAcl;
		}
	}
#endif
	return 0;
}

static int aclchain_inited = 0;

static ssize_t acl_write(struct file *filp, const char __user *buffer, size_t count, loff_t *off)
{
	struct dvCmdAcl_t c;
	int chain;
	DEFINE_SPINLOCK(lock);

	if (count != sizeof(c)) {
		printk("aclwrite:count err(%d,%d)\n", (int)count, sizeof(c));
		return count;
	}

	if (!buffer || copy_from_user(&c, buffer, count))
		return -EFAULT;

	if (!aclchain_inited) {
	//	rtl865x_regist_aclChain("br0", RTL865X_ACL_QOS_USED1, RTL865X_ACL_INGRESS);
	//	rtl865x_regist_aclChain("eth1", RTL865X_ACL_QOS_USED1, RTL865X_ACL_INGRESS);
	//	rtl865x_regist_aclChain("br0", RTL865X_ACL_QOS_USED0, RTL865X_ACL_INGRESS);
	//	rtl865x_regist_aclChain("eth1", RTL865X_ACL_QOS_USED0, RTL865X_ACL_INGRESS);
		rtl865x_regist_aclChain("br0", RTL865X_ACL_QOS_USED0, RTL865X_ACL_EGRESS);
	//	rtl865x_regist_aclChain("eth1", RTL865X_ACL_QOS_USED0, RTL865X_ACL_EGRESS);
		rtl865x_regist_aclChain("br0", RTL865X_ACL_IPV6_USED, RTL865X_ACL_INGRESS);
		rtl865x_regist_aclChain("eth1", RTL865X_ACL_IPV6_USED, RTL865X_ACL_INGRESS);
		aclchain_inited = 1;
	}
	if (strcmp(c.dir, "out") == 0)
		c.rule.direction_ = RTL865X_ACL_EGRESS;
	else
		c.rule.direction_ = RTL865X_ACL_INGRESS;

	if (strcmp(c.chain, "qos") == 0)
		chain = RTL865X_ACL_QOS_USED0;	// -1001
	else
		chain = *((int *)&c.chain[0]);

	if (chain == 0)
		chain = RTL865X_ACL_QOS_USED1;
	spin_lock_bh(&lock);
	if (strcmp(c.cmd, "flush") == 0) {
		rtl865x_flush_allAcl_fromChain(c.intf, chain, c.rule.direction_);
		aclrule_enque_tail(NULL, c.intf, chain, c.rule.direction_, TACL_FREE);
	} else if (strcmp(c.cmd, "add") == 0) {
		rtl865x_add_acl(&c.rule, c.intf, chain);
		if (c.keep_at_tail)
			aclrule_enque_tail(&c.rule, c.intf, chain, -1, TACL_ADD);
	} else if (strcmp(c.cmd, "del") == 0) {
		rtl865x_del_acl(&c.rule, c.intf, chain);
		aclrule_enque_tail(&c.rule, c.intf, chain, -1, TACL_DEL);
	}
	spin_unlock_bh(&lock);

	return count;
}

static int acl_single_open(struct inode *inode, struct file *file)
{
        return single_open(file, acl_show, NULL);
}

struct file_operations acl_proc_fops = {
        .open = acl_single_open,
        .read = seq_read,
        .llseek = seq_lseek,
        .release = single_release,
        .write = acl_write,
};

int rtl_blockoff_source(__be32 ip, int ifindex, int blocking)
{
	struct net_device *dev;
	rtl865x_AclRule_t rule;
	char name[IFNAMSIZ];
	int ret;

	if (ip == INADDR_NONE || ip == INADDR_ANY || IN_MULTICAST(ntohl(ip)))
		return -1;
	dev = dev_get_by_index(&init_net, ifindex);
	if (dev == NULL)
		return -1;
	strcpy(name, dev->name);
	dev_put(dev);
	memset(&rule, 0, sizeof(rule));
	rule.direction_ = RTL865X_ACL_INGRESS;
	rule.actionType_ = RTL865X_ACL_DROP;
	rule.pktOpApp_ = RTL865X_ACL_ALL_LAYER;
	rule.ruleType_ = RTL865X_ACL_IP;
	//rule.netifIdx_ = ;
	rule.srcIpAddr_ = ip;
	rule.srcIpAddrMask_ = 0xffffffff;
	if (blocking) {
		ret = rtl865x_add_acl(&rule, name, RTL865X_ACL_QOS_USED1);
		aclrule_keep_at_tail(name, RTL865X_ACL_QOS_USED1, rule.direction_);
	} else
		ret = rtl865x_del_acl(&rule, name, RTL865X_ACL_QOS_USED1);
	kdmsg_quiet(KDMSG_NET_NETFILTER, "%s %pI4 from %s %s\n",
		(blocking) ? "Blockoff" : "Unblock", &ip, name, (ret) ? "failed" : "done");
	return ret;
}
EXPORT_SYMBOL(rtl_blockoff_source);

int do_acl_igmp(char *name, int trapit)
{
	struct net_device *dev;
	rtl865x_AclRule_t rule;
	int ret;

	dev = dev_get_by_name(&init_net, name);
	if (dev == NULL)
		return -1;
	dev_put(dev);
	memset(&rule, 0, sizeof(rule));
	rule.direction_ = RTL865X_ACL_INGRESS;
	rule.actionType_ = RTL865X_ACL_TOCPU;
	rule.pktOpApp_ = RTL865X_ACL_ALL_LAYER;
	rule.ruleType_ = RTL865X_ACL_IP;
	rule.dstIpAddr_ = 0xe0000000;
	rule.dstIpAddrMask_ = 0xf0000000;
	rule.ipProto_ = IPPROTO_IGMP;
	rule.ipProtoMask_ = 0xff;

	if (trapit) {
		ret = rtl865x_add_acl(&rule, name, RTL865X_ACL_QOS_USED1);
		aclrule_keep_at_tail(name, RTL865X_ACL_QOS_USED1, rule.direction_);
	} else
		ret = rtl865x_del_acl(&rule, name, RTL865X_ACL_QOS_USED1);

	return ret;
}
EXPORT_SYMBOL(do_acl_igmp);
