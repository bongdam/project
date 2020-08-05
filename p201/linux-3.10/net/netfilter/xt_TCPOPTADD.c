/*
 * A module for Add/Modify specific TCP option from TCP packets.
 *
 * Copyright (C) 2018 hf_shi <hf_shi@realsil.com.cn>
 * Copyright (C) Realsil 2018
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <net/ipv6.h>
#include <net/tcp.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_TCPOPTADD.h>

enum {
    FLAG_ADD = 1 << 0,		
    FLAG_MOD = 1 << 1,
};
	

static inline unsigned int optlen(const u_int8_t *opt, unsigned int offset)
{
	/* Beware zero-length options: make finite progress */
	if (opt[offset] <= TCPOPT_NOP || opt[offset+1] == 0)
		return 1;
	else
		return opt[offset+1];
}

static unsigned int
tcpoptadd_mangle_packet(struct sk_buff *skb,
			  const struct xt_action_param *par,
			  unsigned int tcphoff, unsigned int minlen, unsigned int isv6)
{
	const struct xt_tcpoptadd_target_info *info = par->targinfo;
	unsigned int optl, i, j;
	struct sk_buff *new_skb;
	struct ipv6hdr *ipv6h;
	struct tcphdr *tcph;
	struct iphdr *iph;
	u_int16_t n, o;
	u_int8_t *opt;
	int payloadoff;
	int len;
	int cplen;

	/* This is a fragment, no TCP header is available */
	if (par->fragoff != 0)
		return XT_CONTINUE;

	if (!skb_make_writable(skb, skb->len))
		return NF_DROP;

	len = skb->len - tcphoff;
	if (len < (int)sizeof(struct tcphdr))
		return NF_DROP;

	tcph = (struct tcphdr *)(skb_network_header(skb) + tcphoff);
	if (tcph->doff * 4 > len)
		return NF_DROP;

	cplen = ALIGN(info->len,TCPOP_ALGIN);

	/*TCP header will over size*/
	if ((tcph->doff*4 + cplen) > MAX_TCP_OPTION_LEN)
		return NF_DROP;
	
	opt  = (u_int8_t *)tcph;
	
	/*
	 * Walk through all TCP options to check if option existed,
	 */
	//printk("tcp_hdrlen(skb) %d\n",tcp_hdrlen(skb));
	for (i = sizeof(struct tcphdr); i < tcp_hdrlen(skb); i += optl) {
		optl = optlen(opt, i);

		if (i + optl > tcp_hdrlen(skb))
			break;
		//printk("i %d tcp option ID 0x%x\n",i, opt[i],info->id);
		if (opt[i] == info->id) {
			//printk("%s %d\n",__FUNCTION__,__LINE__);
			if(info->op & FLAG_MOD)
			{
				if(optl == info->len)
				{
					/*adjust checkum*/
					tcph = (struct tcphdr *)(skb_network_header(skb) + tcphoff);
					for (j = 0; j < optl-2; ++j) {
						o = opt[i+2+j];
						n = info->value[j];
						if ((i+2+j) % 2 == 0) {
							o <<= 8;
							n <<= 8;
						}
						inet_proto_csum_replace2(&tcph->check, skb, htons(o),
									 htons(n), 0);
					}
					/*new value*/					
					memcpy(opt+i+2,info->value,info->len-2);
				}	
			}
			return XT_CONTINUE;
		}	
	}
	
	/*
	  *add the specificed option & Padding if needed
	  */	
	if (skb_headroom(skb) < cplen || skb_cloned(skb) || skb_shared(skb)){
		new_skb = skb_realloc_headroom(skb, cplen);
		if (!new_skb) {
			printk("skb_realloc_headroom failed\n");
			return XT_CONTINUE;
		}
		kfree_skb(skb);
		skb = new_skb;
	}

	skb_push(skb,cplen);
	payloadoff=tcphoff+(tcph->doff * 4);
	memmove(skb->data,skb_network_header(skb),payloadoff);
	skb_reset_network_header(skb);	
	skb_set_transport_header(skb,tcphoff);
	memcpy(skb->data+payloadoff,info,info->len);
	if(cplen > (info->len))
		memset(skb->data+payloadoff+info->len,TCPOPT_NOP,(cplen-info->len));

	/*checksum for adding option*/
	opt = skb->data+payloadoff;	
	tcph = (struct tcphdr *)(skb_network_header(skb) + tcphoff);
	for (j = 0; j < cplen; ++j) {
		o = 0;
		n = opt[j];
		if (j % 2 == 0) {
			o <<= 8;
			n <<= 8;
		}
		inet_proto_csum_replace2(&tcph->check, skb, htons(o),
					 htons(n), 0);
	}

	/*update TCP header len & checksum*/
	o = *((unsigned short *)((void *)tcph+12));
	n = (tcph->doff * 4) + cplen;
	tcph->doff = n/4;
	n = *((unsigned short *)((void *)tcph+12));
	csum_replace2(&tcph->check,o,n);

	/*TCP psudeo header  & checksum*/
	o = len;
	n = o + cplen;
	csum_replace2(&tcph->check,htons(o),htons(n));
	
	/*Update network header & checksum*/
	if(isv6){
		ipv6h = ipv6_hdr(skb);
		ipv6h->payload_len += htons(cplen); 
	} else {
		iph = ip_hdr(skb);
		csum_replace2(&iph->check,iph->tot_len,iph->tot_len + htons(cplen));		
		iph->tot_len += htons(cplen);
	}
	
	return XT_CONTINUE;
}

static unsigned int
tcpoptadd_tg4(struct sk_buff *skb, const struct xt_action_param *par)
{
	return tcpoptadd_mangle_packet(skb, par, ip_hdrlen(skb),
	       sizeof(struct iphdr) + sizeof(struct tcphdr),0);
}

#if IS_ENABLED(CONFIG_IP6_NF_MANGLE)
static unsigned int
tcpoptadd_tg6(struct sk_buff *skb, const struct xt_action_param *par)
{
	struct ipv6hdr *ipv6h = ipv6_hdr(skb);
	int tcphoff;
	u_int8_t nexthdr;
	__be16 frag_off;

	nexthdr = ipv6h->nexthdr;
	tcphoff = ipv6_skip_exthdr(skb, sizeof(*ipv6h), &nexthdr, &frag_off);
	if (tcphoff < 0)
		return NF_DROP;

	return tcpoptadd_mangle_packet(skb, par, tcphoff,
	       sizeof(*ipv6h) + sizeof(struct tcphdr),1);
}
#endif

static struct xt_target tcpoptadd_tg_reg[] __read_mostly = {
	{
		.name       = "TCPOPTADD",
		.family     = NFPROTO_IPV4,
		.table      = "mangle",
		.proto      = IPPROTO_TCP,
		.target     = tcpoptadd_tg4,
		.targetsize = sizeof(struct xt_tcpoptadd_target_info),
		.me         = THIS_MODULE,
	},
#if IS_ENABLED(CONFIG_IP6_NF_MANGLE)
	{
		.name       = "TCPOPTADD",
		.family     = NFPROTO_IPV6,
		.table      = "mangle",
		.proto      = IPPROTO_TCP,
		.target     = tcpoptadd_tg6,
		.targetsize = sizeof(struct xt_tcpoptadd_target_info),
		.me         = THIS_MODULE,
	},
#endif
};

static int __init tcpoptadd_tg_init(void)
{
	return xt_register_targets(tcpoptadd_tg_reg,
				   ARRAY_SIZE(tcpoptadd_tg_reg));
}

static void __exit tcpoptadd_tg_exit(void)
{
	xt_unregister_targets(tcpoptadd_tg_reg,
			      ARRAY_SIZE(tcpoptadd_tg_reg));
}

module_init(tcpoptadd_tg_init);
module_exit(tcpoptadd_tg_exit);
MODULE_AUTHOR("hf_shi <hf_shi@realsil.com.cn>");
MODULE_DESCRIPTION("Xtables: TCP option adding");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_TCPOPTADD");
MODULE_ALIAS("ip6t_TCPOPTADD");
