#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/random.h>

#include <linux/netdevice.h>

#include <crypto/aes.h>

#include <net/rtl/rtl_types.h>
#include <net/rtl/rtl_glue.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,4,0)
#include "../../net/rtl819x/AsicDriver/rtl865xc_asicregs.h"
#else
#include <asm/rtl865x/rtl865xc_asicregs.h>
#endif

#include "rtl_ipsec.h"

#include <net/net_namespace.h>
#include <net/sock.h>
#include <net/netlink.h>

#include <net/checksum.h>
#include <net/udp.h>

#include "crypto_engine/sw_sim/aes.h"
#include "rtl_fast_openvpn.h"

OpenVPN_Info vpn_client_info[MAX_CLIENT_NUM];
//u8 tmp_client_hdr[MAX_TMP_CLIENT_NUM][MAX_OUT_LAYER_HDR_LEN];

Shared_OpenVPN_Info vpn_shared_info;

struct sock *nl_openvpn_sk=NULL;
static u32 rtk_openvpn_pid;

static u8 engine_init_flag=0;
//static u32 count_call_hw_engine=0;

void dump_openvpn_info(u8 *data, u32 len, u32 space_break)
{
	int i;
	for(i=0;i<len;i++)
	{
		if(i && i%space_break==0)
			printk(" ");
		
		printk("%02x", data[i]);
	}
	printk("\n\n");
}

#if 0
inline void *UNCACHED_MALLOC(int size)
{
	return ((void *)(((unsigned int)kmalloc(size, GFP_ATOMIC)) | UNCACHE_MASK));
}
#endif

#if 1
inline void GenerateRandomData(unsigned char * data, unsigned int len)
{
        unsigned int i, num;
        unsigned char *pRu8;
#ifdef __LINUX_2_6__
        srandom32(jiffies);     
#endif

        for (i=0; i<len; i++) {
#ifdef __LINUX_2_6__
                num = random32();
#else
                get_random_bytes(&num, 4);
#endif
                pRu8 = (unsigned char*)&num;
                data[i] = pRu8[0]^pRu8[1]^pRu8[2]^pRu8[3];
        }
}
#endif

#if 0
inline void GenerateRandomData(unsigned char * data, unsigned int len)
{
        get_random_bytes(data, len);                
}
#endif

inline void increaseVI(u8 *vi, int AddCount)
{
	int  i;

	for (i=0; i< IV_LEN; i++)
	{
		if (vi[i] + AddCount <= 0xff)
		{
			vi[i] += AddCount;
			return ;
		}
		else
		{
			//vi[i] += AddCount;
		}
	}
	//printk("\n%s calling GenerateRandomData()!!!\n",__FUNCTION__);
	GenerateRandomData(vi, IV_LEN);
	return ;
}


void key_update_timeout(unsigned long client_idx)
{
	printk("\nKey Update Timeout!!!\n");
	vpn_client_info[client_idx].enc_key_index=KS_PRIMARY;
	vpn_client_info[client_idx].pkt_id=1;	
}

void rtk_openvpn_netlink_send(int pid, struct sock *nl_sk, char *data, int data_len)
{	
	struct nlmsghdr *nlh;
	struct sk_buff *skb;
	int rc, len;
	
	if(data_len>MAX_OPENVPN_PAYLOAD_LEN)
	{
		printk("%s:%d##date len is too long!\n",__FUNCTION__,__LINE__);
		return;
	}	

	len = NLMSG_SPACE(MAX_OPENVPN_PAYLOAD_LEN);
	skb = alloc_skb(len, GFP_ATOMIC);
	if(!skb)
	{
		printk(KERN_ERR "net_link: allocate failed.\n");
		return;
	}
	
	nlh = nlmsg_put(skb,0,0,0,len,0);

	if(nlh==NULL)
	{
		printk("data_len=%d len=%d nlh is NULL!\n\n", data_len, len);
		return;
	}
	
	NETLINK_CB(skb).portid = 0; /* from kernel */
	memcpy(NLMSG_DATA(nlh), data, data_len);
	
	nlh->nlmsg_len=data_len+NLMSG_HDRLEN;
	
	rc = netlink_unicast(nl_sk, skb, pid, MSG_DONTWAIT);
	
	if (rc < 0) 
		printk(KERN_ERR "net_link: can not unicast skb (%d)\n", rc);	
	
	return;
}

void delete_client_info(int client_idx)
{
	if(vpn_client_info[client_idx].active_flag)
	{
		del_timer(&(vpn_client_info[client_idx].key_update_timer));
		del_timer(&(vpn_client_info[client_idx].ping_send_timer));
		del_timer(&(vpn_client_info[client_idx].ping_rec_timer));
		
		vpn_client_info[client_idx].active_flag=0;
		vpn_client_info[client_idx].pkt_id=1;
		vpn_client_info[client_idx].enc_key_index=0;
		vpn_client_info[client_idx].soft_rest_flag=0;
		vpn_client_info[client_idx].key_info[KS_PRIMARY].key_id=0;
		vpn_client_info[client_idx].key_info[KS_LAME_DUCK].key_id=0;

		if(vpn_client_info[client_idx].key_info[KS_PRIMARY].enc_key!=NULL)
		{
			kfree((void *)CACHED_ADDRESS(vpn_client_info[client_idx].key_info[KS_PRIMARY].enc_key));
			kfree((void *)CACHED_ADDRESS(vpn_client_info[client_idx].key_info[KS_PRIMARY].dec_key));
			kfree((void *)CACHED_ADDRESS(vpn_client_info[client_idx].key_info[KS_PRIMARY].enc_hmac_key));
			kfree((void *)CACHED_ADDRESS(vpn_client_info[client_idx].key_info[KS_PRIMARY].dec_hmac_key));
			kfree((void *)CACHED_ADDRESS(vpn_client_info[client_idx].key_info[KS_PRIMARY].iv));
			vpn_client_info[client_idx].key_info[KS_PRIMARY].enc_key=NULL;
		}

		if(vpn_client_info[client_idx].key_info[KS_LAME_DUCK].enc_key!=NULL)
		{
			kfree((void *)CACHED_ADDRESS(vpn_client_info[client_idx].key_info[KS_LAME_DUCK].enc_key));
			kfree((void *)CACHED_ADDRESS(vpn_client_info[client_idx].key_info[KS_LAME_DUCK].dec_key));
			kfree((void *)CACHED_ADDRESS(vpn_client_info[client_idx].key_info[KS_LAME_DUCK].enc_hmac_key));
			kfree((void *)CACHED_ADDRESS(vpn_client_info[client_idx].key_info[KS_LAME_DUCK].dec_hmac_key));
			kfree((void *)CACHED_ADDRESS(vpn_client_info[client_idx].key_info[KS_LAME_DUCK].iv));
			vpn_client_info[client_idx].key_info[KS_LAME_DUCK].enc_key=NULL;
		}
		
		memset(vpn_client_info[client_idx].peer_layer_hdr, 0, MAX_OUT_LAYER_HDR_LEN);
	}
}

void ping_rec_timeout(unsigned long client_idx)
{
	printk("\nPing Rec Timeout!!!\n");
	//notifiy upper openvpn daemon to restart
	
	u8 send_buf[64]={0};
	int offset=0;
	
	memcpy(send_buf+offset, &(vpn_client_info[client_idx].peer_ip), sizeof(u32));
	offset+=sizeof(u32);

	memcpy(send_buf+offset, &(vpn_client_info[client_idx].virtual_ip), sizeof(u32));
	offset+=sizeof(u32);

	memcpy(send_buf+offset, &(vpn_client_info[client_idx].peer_port), sizeof(u16));
	offset+=sizeof(u16);
	
	rtk_openvpn_netlink_send(rtk_openvpn_pid, nl_openvpn_sk, send_buf, offset);

	delete_client_info(client_idx);
}

void ping_send_timeout(unsigned long client_idx)
{
	//printk("\nPing Send Timeout!!!\n");
	int padding_len, i, header_len;
	int pppoe_hdr_len=0;
	unsigned char *data;
	//printk("\nPing Send Timeout!!!\n");
	//send ping packet to client
	struct sk_buff *skb=NULL;
	
	if(vpn_client_info[client_idx].active_flag==0)
		return;
	
	skb=dev_alloc_skb(512);

	if(skb==NULL)
	{
		printk("\n%s alloc skb fail!!!\n",__FUNCTION__);
		return;
	}
	
	data = rtl_vpn_get_skb_data(skb);
	
	memset(data, 0, 512);
	
	header_len = vpn_shared_info.local_layer_hdr_len+vpn_shared_info.digest_len+IV_LEN+PKT_ID_LEN;
	memcpy(data, vpn_client_info[client_idx].peer_layer_hdr, vpn_shared_info.local_layer_hdr_len);

	memcpy(data+header_len, ping_string, PING_STRING_SIZE);	

	//padding
	padding_len=CBC_BLOCK_SIZE-(PING_STRING_SIZE+PKT_ID_LEN)%CBC_BLOCK_SIZE;	
	for(i=0; i<padding_len; i++)
		data[header_len+PING_STRING_SIZE+i]=padding_len;
	
	//*((u32 *)(data+header_len-PKT_ID_LEN))=0;	
	
	*((u8 *)(data+header_len-1))=0xfa;
	//*((u8 *)(data+vpn_shared_info.local_layer_hdr_len-1))=0x30;
	*((u8 *)(data+vpn_shared_info.local_layer_hdr_len-1))=0;


	//skb->len=0;
	rtl_vpn_set_skb_len(skb, 0);
	rtl_vpn_skb_put(skb, header_len+PING_STRING_SIZE+padding_len);

	//skb->len=header_len+PING_STRING_SIZE+padding_len;
	//skb->tail=skb->data+skb->len;
	
	*((u16*)(data+vpn_shared_info.local_layer_hdr_len-5))=rtl_vpn_get_skb_len(skb)-vpn_shared_info.local_layer_hdr_len+9;
	
	*((u16*)(data+vpn_shared_info.local_layer_hdr_len-27))=rtl_vpn_get_skb_len(skb)-vpn_shared_info.local_layer_hdr_len+29;

	if(vpn_shared_info.local_layer_hdr_len==MAX_OUT_LAYER_HDR_LEN)
	{
		pppoe_hdr_len=PPP_HDR_LEN;
		*((u16*)(data+ETH_HDR_HLEN+4))=rtl_vpn_get_skb_len(skb)-IP_HDR_LEN;
	}
	
	//skb_reset_mac_header(skb); 				//set mac header
	//skb_set_network_header(skb,ETH_HDR_HLEN+pppoe_hdr_len);			//set ip header
	//skb_set_transport_header(skb,ETH_HDR_HLEN+IP_HDR_LEN+pppoe_hdr_len); 	//set transport header

	//rtl_vpn_set_skb_dev(skb, vpn_shared_info.wan_dev);
	if(vpn_shared_info.wan_dev==NULL)
	{
		printk("\nvpn_shared_info.wan_dev is NULL!!!\n");
		return;
	}
	//else
	//	printk("\n%s dev_name=%s\n",__FUNCTION__,((struct net_device *)(vpn_shared_info.wan_dev))->name);
	
	//skb->dev=(struct net_device *)(vpn_shared_info.wan_dev);
	//if(vpn_shared_info.local_layer_hdr_len==MAX_OUT_LAYER_HDR_LEN)
		//vpn_shared_info.wan_dev=rtl_vpn_get_dev_by_name("eth1");
	
	rtl_vpn_set_skb_dev(skb, vpn_shared_info.wan_dev);

	//printk("\n%s Send Ping Packet:\n",__FUNCTION__);
	//dump_openvpn_info(skb->data, skb->len, 1);

	rtl_vpn_call_skb_ndo_start_xmit(skb);	
}

int lookup_client_by_ip_and_port(u32 peer_ip, u16 peer_port, int flag)
{
	int i;
	int found=0;
	for(i=0;i<MAX_CLIENT_NUM;i++)
	{
		if(vpn_client_info[i].peer_ip==peer_ip && vpn_client_info[i].peer_port==peer_port)
		{
			//printk("%s Found The Client %d\n\n",__FUNCTION__,i);
			found=1;
			return i;
		}
	}	

	if(flag!=ADD_CLIENT_FLAG)
		return i;

	if(i==MAX_CLIENT_NUM)
	{
		for(i=0;i<MAX_CLIENT_NUM;i++)
		{
			if(vpn_client_info[i].active_flag==0)
			{
				if(vpn_client_info[i].key_info[KS_PRIMARY].enc_key==NULL)
				{					
					vpn_client_info[i].key_info[KS_PRIMARY].enc_key=(u8 *) UNCACHED_MALLOC(CRYPT_KEY_LEN);
					vpn_client_info[i].key_info[KS_PRIMARY].dec_key=(u8 *) UNCACHED_MALLOC(CRYPT_KEY_LEN);
					vpn_client_info[i].key_info[KS_PRIMARY].enc_hmac_key=(u8 *) UNCACHED_MALLOC(HMAC_KEY_LEN);
					vpn_client_info[i].key_info[KS_PRIMARY].dec_hmac_key=(u8 *) UNCACHED_MALLOC(HMAC_KEY_LEN);
					vpn_client_info[i].key_info[KS_PRIMARY].iv=(u8 *) UNCACHED_MALLOC(IV_LEN);						
					vpn_client_info[i].key_info[KS_PRIMARY].key_id=0;
				}
				if(vpn_client_info[i].key_info[KS_LAME_DUCK].enc_key==NULL)
				{					
					vpn_client_info[i].key_info[KS_LAME_DUCK].enc_key=(u8 *) UNCACHED_MALLOC(CRYPT_KEY_LEN);
					vpn_client_info[i].key_info[KS_LAME_DUCK].dec_key=(u8 *) UNCACHED_MALLOC(CRYPT_KEY_LEN);
					vpn_client_info[i].key_info[KS_LAME_DUCK].enc_hmac_key=(u8 *) UNCACHED_MALLOC(HMAC_KEY_LEN);
					vpn_client_info[i].key_info[KS_LAME_DUCK].dec_hmac_key=(u8 *) UNCACHED_MALLOC(HMAC_KEY_LEN);
					vpn_client_info[i].key_info[KS_LAME_DUCK].iv=(u8 *) UNCACHED_MALLOC(IV_LEN);						
					vpn_client_info[i].key_info[KS_LAME_DUCK].key_id=0;					
				}				
				//printk("%s return Client %d\n\n",__FUNCTION__,i);
				return i;
			}
		}
		if(i==MAX_CLIENT_NUM)
		{
			printk("Client Reach to Max Number!\n");
			return -1;
		}			
	}
	return -1;
}

void rtk_openvpn_netlink_receive(struct sk_buff *skb)
{
	int len, client_idx=-1, offset=0;
	u8 recv_buf[KEY_BUF_LEN];
	u32 peer_ip, virtual_ip;
	u16 peer_port;
	struct nlmsghdr *nlh=NULL;
	AES_KEY aes_key;
	
	if (rtl_vpn_get_skb_len(skb) < NLMSG_SPACE(0))
		return;
		
	nlh = nlmsg_hdr(skb);
	len=rtl_vpn_get_skb_len(skb)-NLMSG_HDRLEN;
	
	rtk_openvpn_pid = nlh->nlmsg_pid; /*pid of sending process */

	memcpy(recv_buf, NLMSG_DATA(nlh), len);
	
	if(nlh->nlmsg_flags==CRYPT_KEY_FLAG)
	{
		while(offset<len)
		{
			switch(recv_buf[offset])
			{
				case PEER_IP_FLAG: //L
					memcpy(&peer_ip, recv_buf+offset+2, recv_buf[offset+1]);
					printk("\nOpenVPN CLIENT IP=%04x\n\n", peer_ip);					
					break;
					
				case PEER_PORT_FLAG: //B
					memcpy(&peer_port, recv_buf+offset+2, recv_buf[offset+1]);
					peer_port=ntohs(peer_port);
					client_idx=lookup_client_by_ip_and_port(peer_ip, peer_port, ADD_CLIENT_FLAG);
					
					if(client_idx<0 || client_idx>=MAX_CLIENT_NUM)
					{
						printk("\n%s##Invalid Client Index!\n\n",__FUNCTION__);
						return;
					}	
					vpn_client_info[client_idx].peer_ip=peer_ip;
					vpn_client_info[client_idx].peer_port=peer_port;

					printk("\nOpenVPN CLIENT %d IP=%04x PORT=%02x\n\n", client_idx, peer_ip, peer_port);
					break;

				case ENC_KEY_FLAG:
					memcpy(vpn_client_info[client_idx].key_info[KS_LAME_DUCK].enc_key, vpn_client_info[client_idx].key_info[KS_PRIMARY].enc_key, recv_buf[offset+1]);
					memcpy(vpn_client_info[client_idx].key_info[KS_PRIMARY].enc_key, recv_buf+offset+2, recv_buf[offset+1]);
					vpn_client_info[client_idx].crypt_key_len=recv_buf[offset+1];

					//printk("OpenVPN CLIENT %d ENC KEY LEN=%d:\n", client_idx, vpn_client_info[client_idx].crypt_key_len);
					//dump_openvpn_info(vpn_client_info[client_idx].key_info[KS_PRIMARY].enc_key, vpn_client_info[client_idx].crypt_key_len, 4);

					memcpy(vpn_client_info[client_idx].key_info[KS_LAME_DUCK].iv, vpn_client_info[client_idx].key_info[KS_PRIMARY].iv, IV_LEN);
					memcpy(vpn_client_info[client_idx].key_info[KS_PRIMARY].iv, recv_buf+offset+2, IV_LEN);
					break;

				case HMAC_ENC_KEY_FLAG:
					memcpy(vpn_client_info[client_idx].key_info[KS_LAME_DUCK].enc_hmac_key, vpn_client_info[client_idx].key_info[KS_PRIMARY].enc_hmac_key, recv_buf[offset+1]);
					memcpy(vpn_client_info[client_idx].key_info[KS_PRIMARY].enc_hmac_key, recv_buf+offset+2, recv_buf[offset+1]);
					vpn_client_info[client_idx].hmac_key_len=recv_buf[offset+1];

					//printk("OpenVPN CLIENT %d ENC HMAC KEY LEN=%d:\n", client_idx, vpn_client_info[client_idx].hmac_key_len);
					//dump_openvpn_info(vpn_client_info[client_idx].enc_hmac_key, vpn_client_info[client_idx].hmac_key_len, 4);
					
					break;

				case DEC_KEY_FLAG:					
					memcpy(vpn_client_info[client_idx].key_info[KS_LAME_DUCK].dec_key, vpn_client_info[client_idx].key_info[KS_PRIMARY].dec_key, recv_buf[offset+1]);
					memcpy(vpn_client_info[client_idx].key_info[KS_PRIMARY].dec_key, recv_buf+offset+2, recv_buf[offset+1]);
					//printk("OpenVPN CLIENT %d DEC KEY LEN=%d:\n", client_idx, vpn_client_info[client_idx].crypt_key_len);
					//dump_openvpn_info(vpn_client_info[client_idx].dec_key, vpn_client_info[client_idx].crypt_key_len, 4);
				
					AES_set_encrypt_key(vpn_client_info[client_idx].key_info[KS_PRIMARY].dec_key, recv_buf[offset+1]*8, &aes_key);
					memcpy(vpn_client_info[client_idx].key_info[KS_PRIMARY].dec_key, &aes_key.rd_key[4*14], 16);
					memcpy(vpn_client_info[client_idx].key_info[KS_PRIMARY].dec_key+16, &aes_key.rd_key[4*13], 16);
					
					break;

				case HMAC_DEC_KEY_FLAG:						
					memcpy(vpn_client_info[client_idx].key_info[KS_LAME_DUCK].dec_hmac_key, vpn_client_info[client_idx].key_info[KS_PRIMARY].dec_hmac_key, recv_buf[offset+1]);
					memcpy(vpn_client_info[client_idx].key_info[KS_PRIMARY].dec_hmac_key, recv_buf+offset+2, recv_buf[offset+1]);
					//printk("OpenVPN CLIENT %d DEC HMAC KEY LEN=%d:\n", client_idx, vpn_client_info[client_idx].hmac_key_len);
					//dump_openvpn_info(vpn_client_info[client_idx].dec_hmac_key, vpn_client_info[client_idx].hmac_key_len, 4);

					vpn_client_info[client_idx].enc_key_index=KS_PRIMARY;
					
					if(vpn_client_info[client_idx].soft_rest_flag)
					{			
						vpn_client_info[client_idx].key_info[KS_LAME_DUCK].key_id=vpn_client_info[client_idx].key_info[KS_PRIMARY].key_id;					
						vpn_client_info[client_idx].key_info[KS_PRIMARY].key_id++;
						if(vpn_client_info[client_idx].key_info[KS_PRIMARY].key_id>7)
							vpn_client_info[client_idx].key_info[KS_PRIMARY].key_id=1;
					
						vpn_client_info[client_idx].enc_key_index=KS_LAME_DUCK;
						//printk("\nCalling mod_timer() to start timer!!!\n");
						mod_timer(&(vpn_client_info[client_idx].key_update_timer), jiffies+RTL_SECONDS_TO_JIFFIES(vpn_shared_info.key_update_time));
						vpn_client_info[client_idx].soft_rest_flag=0;
					}
					break;
					
				default:
					printk("%s##Invalid Flag!\n",__FUNCTION__);
					break;						
			}
			offset+=2+recv_buf[offset+1];
		}
	}
	if(nlh->nlmsg_flags==CONFIG_OPTION_FLAG)
	{
		while(offset<len)
		{
			switch(recv_buf[offset])
			{
				case PORT_NUM_FLAG:   //B
					memcpy(&vpn_shared_info.local_port, recv_buf+offset+2, recv_buf[offset+1]);
					vpn_shared_info.local_port=ntohs(vpn_shared_info.local_port);
					printk("\nOpenVPN SERVER PORT=%02x\n\n", vpn_shared_info.local_port);
					break;
					
				case UPDATE_KEY_TIME_FLAG:
					memcpy(&vpn_shared_info.key_update_time, recv_buf+offset+2, recv_buf[offset+1]);
					printk("\nOpenVPN SERVER KEY UPDATE TIME: %d\n", vpn_shared_info.key_update_time);
					break;	
					
				case PING_REC_TIME_FLAG:
					memcpy(&vpn_shared_info.ping_rec_time, recv_buf+offset+2, recv_buf[offset+1]);
					printk("\nOpenVPN PING REC TIME: %d\n", vpn_shared_info.ping_rec_time);
					break;
					
				case PING_SEND_TIME_FLAG:
					memcpy(&vpn_shared_info.ping_send_time, recv_buf+offset+2, recv_buf[offset+1]);
					printk("\nOpenVPN PING SEND TIME: %d\n", vpn_shared_info.ping_send_time);
					break;
					
				case AUTH_NONE_FLAG:
					vpn_shared_info.auth_none=recv_buf[offset+2];
					vpn_shared_info.digest_len=0;
					printk("\nOpenVPN AUTH NONE: %d\n", vpn_shared_info.auth_none);
					break;
				default:
					printk("%s##Invalid Flag!\n",__FUNCTION__);
					break;						
			}
			offset+=2+recv_buf[offset+1];
		}		
	}
	if(nlh->nlmsg_flags==VIRTUAL_IP_FLAG)
	{
		while(offset<len)
		{
			switch(recv_buf[offset])
			{
				case PEER_IP_FLAG: //L
					memcpy(&peer_ip, recv_buf+offset+2, recv_buf[offset+1]);
					break;
					
				case PEER_PORT_FLAG: //L
					memcpy(&peer_port, recv_buf+offset+2, recv_buf[offset+1]);

					client_idx=lookup_client_by_ip_and_port(peer_ip, peer_port, ADD_CLIENT_FLAG);
					
					if(client_idx<0 || client_idx>=MAX_CLIENT_NUM)
					{
						printk("%s##Invalid Client Index!\n",__FUNCTION__);
						return;
					}					
					printk("\nOpenVPN CLIENT %d IP=%04x PORT=%02x #####\n\n", client_idx, peer_ip, peer_port);
					break;

				case VIRTUAL_IP_FLAG: //B
					memcpy(&virtual_ip, recv_buf+offset+2, recv_buf[offset+1]);
					virtual_ip=ntohl(virtual_ip);
					vpn_client_info[client_idx].peer_ip=peer_ip;
					vpn_client_info[client_idx].peer_port=peer_port;
					vpn_client_info[client_idx].virtual_ip=virtual_ip;
					vpn_client_info[client_idx].active_flag=1;						
					
					init_timer(&(vpn_client_info[client_idx].key_update_timer));
					vpn_client_info[client_idx].key_update_timer.data = (unsigned long)client_idx;
					vpn_client_info[client_idx].key_update_timer.function = key_update_timeout;

					init_timer(&(vpn_client_info[client_idx].ping_rec_timer));
					vpn_client_info[client_idx].ping_rec_timer.data = (unsigned long)client_idx;
					vpn_client_info[client_idx].ping_rec_timer.function = ping_rec_timeout;
					mod_timer(&(vpn_client_info[client_idx].ping_rec_timer), jiffies+RTL_SECONDS_TO_JIFFIES(vpn_shared_info.ping_rec_time));
					
					init_timer(&(vpn_client_info[client_idx].ping_send_timer));
					vpn_client_info[client_idx].ping_send_timer.data = (unsigned long)client_idx;
					vpn_client_info[client_idx].ping_send_timer.function = ping_send_timeout;
					mod_timer(&(vpn_client_info[client_idx].ping_send_timer), jiffies+RTL_SECONDS_TO_JIFFIES(vpn_shared_info.ping_send_time));
					
					printk("\nOpenVPN CLIENT VIRTUAL IP=%04x\n\n", virtual_ip);

					if(engine_init_flag==0)
					{
						engine_init_flag=1;
						rtl_ipsecEngine_init(DEFAULT_DESC_NUM, 2);
						rtl_ipsecSetOption(RTL_IPSOPT_SAWB, 1);
					}

					break;
					
				default:
					printk("%s##Invalid Flag!\n",__FUNCTION__);
					break;						
			}
			offset+=2+recv_buf[offset+1];
		}
	}	
	if(nlh->nlmsg_flags==DEL_IP_PORT_FLAG)
	{
		while(offset<len)
		{
			switch(recv_buf[offset])
			{
				case PEER_IP_FLAG:
					memcpy(&peer_ip, recv_buf+offset+2, recv_buf[offset+1]);
					break;
					
				case PEER_PORT_FLAG:
					memcpy(&peer_port, recv_buf+offset+2, recv_buf[offset+1]);

					client_idx=lookup_client_by_ip_and_port(peer_ip, peer_port, DEL_CLIENT_FLAG);
					
					if(client_idx<0 || client_idx>=MAX_CLIENT_NUM)
					{
						printk("%s##Invalid Client Index!\n",__FUNCTION__);
						return;
					}	
					
					printk("\nOpenVPN CLEAR CLIENT %d IP=%04x PORT=%02x !!!!!\n", client_idx, peer_ip, peer_port);

					delete_client_info(client_idx);					
					break;			
					
				default:
					printk("%s##Invalid Flag!\n",__FUNCTION__);
					break;						
			}
			offset+=2+recv_buf[offset+1];
		}
	}	
	if(nlh->nlmsg_flags==EXITING_FLAG)
	{
		//TODO delete all client info
		printk("\n%s recv openvpn exit event!!!\n",__FUNCTION__);
		int i;
		for(i=0; i<MAX_CLIENT_NUM; i++)
		{
			delete_client_info(i);
		}
		
		vpn_shared_info.local_port=0;
		vpn_shared_info.wan_dev=NULL;
		vpn_shared_info.tun_dev=NULL;
		vpn_shared_info.out_dev=NULL;

		#if 0
		kfree((void *) CACHED_ADDRESS(vpn_shared_info.enc_data));
		kfree((void *) CACHED_ADDRESS(vpn_shared_info.dec_data));
		kfree((void *) CACHED_ADDRESS(vpn_shared_info.CryptResult));
		kfree((void *) CACHED_ADDRESS(vpn_shared_info.DesCryptResult));
		kfree((void *) CACHED_ADDRESS(vpn_shared_info.digest));

		if(nl_openvpn_sk!=NULL)
		{		
			printk("\n%s call netlink_kernel_release()!!!\n",__FUNCTION__);
			netlink_kernel_release(nl_openvpn_sk);
			nl_openvpn_sk=NULL;
		}
		#endif
	}	
}

int get_openvpn_port(void)
{
	return vpn_shared_info.local_port;
}

inline int is_openvpn_fragment(struct sk_buff *skb)
{
	int padding_len, header_len, skb_len;
	struct net_device	*out_dev=NULL;

	if(vpn_shared_info.out_dev==NULL)
	{
		printk("\n%s vpn_shared_info.out_dev==NULL!!!\n",__FUNCTION__);
		return 0;
	}
	
	out_dev=(struct net_device *)vpn_shared_info.out_dev;
	skb_len=rtl_vpn_get_skb_len(skb);
	
	//printk("\n%s:%d out_dev->name=%s out_dev->mtu=%d\n",__FUNCTION__,__LINE__,out_dev->name, out_dev->mtu);			
	
	header_len = FRAGMENT_OUT_LAYER_HDR_LEN+vpn_shared_info.digest_len+IV_LEN+PKT_ID_LEN;

	if(skb_len+header_len>out_dev->mtu)
		return 1;
	
	padding_len=CBC_BLOCK_SIZE-(skb_len+PKT_ID_LEN)%CBC_BLOCK_SIZE;	
	
	if(skb_len+padding_len+header_len>out_dev->mtu)
		return 1;
	else
		return 0;	
}

int check_send_pkt(struct sk_buff *skb, int flag)
{	
	u8 pkt_type;
	u8 op;
	int i;
	u32 peer_ip;
	u16 peer_port;
	int net_hdr_len, client_idx;
	int fragment_limit, padding_len, header_len;
	unsigned char *data;
	//struct iphdr *iph;
	//struct udphdr *udph;

	if(rtl_vpn_get_skb_len(skb) < MAX_OUT_LAYER_HDR_LEN)
		return 0;

	data = rtl_vpn_get_skb_data(skb);
	
	if(flag==1 && *((uint16*)(data+34))==vpn_shared_info.local_port)
	{
		net_hdr_len=ETH_HDR_HLEN+IP_HDR_LEN+UDP_HDR_LEN;  
		//printk("%s net_hdr_len=%d\n",__FUNCTION__,net_hdr_len);
			
		pkt_type=data[net_hdr_len];
		op=pkt_type >> P_OPCODE_SHIFT;		
		
		if(op==0)
			return 1; //data pkt

		if(op==P_DATA_V1)
			return 0; //data pkt
		
		if(op>=P_FIRST_OPCODE && op<=P_LAST_OPCODE)
		{
			if(op==P_CONTROL_HARD_RESET_SERVER_V2)
			{
				vpn_shared_info.local_layer_hdr_len=net_hdr_len+1;
				vpn_shared_info.wan_dev=(void*)rtl_vpn_get_skb_dev(skb);
				
				printk("\n%s:%d vpn_shared_info.wan_dev NAME %s\n\n",__FUNCTION__,__LINE__, ((struct net_device *)(vpn_shared_info.wan_dev))->name);

				vpn_shared_info.out_dev=vpn_shared_info.wan_dev;
				printk("\n%s:%d vpn_shared_info.out_dev NAME %s\n\n",__FUNCTION__,__LINE__, ((struct net_device *)(vpn_shared_info.out_dev))->name);

				peer_ip= *((uint32*)(data+30));
				peer_port= *((uint16*)(data+36));

				client_idx=lookup_client_by_ip_and_port(peer_ip, peer_port, ADD_CLIENT_FLAG);
				if(client_idx<0 || client_idx>=MAX_CLIENT_NUM)
				{
					printk("%s##Invalid Client Index!\n",__FUNCTION__);
					return 0;
				}	

				memset(vpn_client_info[client_idx].peer_layer_hdr, 0, net_hdr_len+1);					
				memcpy(vpn_client_info[client_idx].peer_layer_hdr, data, net_hdr_len+1);
				vpn_client_info[client_idx].pkt_id=1;	
				vpn_client_info[client_idx].key_info[KS_PRIMARY].key_id=0;
				vpn_client_info[client_idx].key_info[KS_LAME_DUCK].key_id=0;
				vpn_client_info[client_idx].active_flag=0;
				vpn_client_info[client_idx].soft_rest_flag=0;
				vpn_client_info[client_idx].enc_key_index=0;

				#if 0
				for(i=0;i<MAX_CLIENT_NUM;i++)
				if(vpn_client_info[i].peer_ip==peer_ip && vpn_client_info[i].peer_port==peer_port)
				{
					memset(vpn_client_info[i].peer_layer_hdr, 0, net_hdr_len+1);					
					memcpy(vpn_client_info[i].peer_layer_hdr, data, net_hdr_len+1);
					vpn_client_info[i].pkt_id=0;	
					vpn_client_info[i].key_info[KS_PRIMARY].key_id=0;
					vpn_client_info[i].key_info[KS_LAME_DUCK].key_id=0;
					vpn_client_info[i].active_flag=0;
					vpn_client_info[i].soft_rest_flag=0;
					vpn_client_info[i].enc_key_index=0;
					
					//mod_timer(&(vpn_client_info[i].ping_send_timer), jiffies+RTL_SECONDS_TO_JIFFIES(vpn_shared_info.ping_send_time));
					break;
				}
				#endif
			}
			if(op==P_CONTROL_SOFT_RESET_V1)
			{
				printk("\nSend Soft Reset Packet!\n");
				peer_ip= *((uint32*)(data+30));
				peer_port= *((uint16*)(data+36));

				for(i=0;i<MAX_CLIENT_NUM;i++)
				if(vpn_client_info[i].peer_ip==peer_ip && vpn_client_info[i].peer_port==peer_port)
				{									
					vpn_client_info[i].soft_rest_flag=1;
					break;
				}				
			}
			return 2;  //ctrl pkt
		}
	}

	if(flag==2 && *((uint16*)(data+42))==vpn_shared_info.local_port)
	{
		net_hdr_len=ETH_HDR_HLEN+PPP_HDR_LEN+IP_HDR_LEN+UDP_HDR_LEN;
		pkt_type=data[net_hdr_len];
		op=pkt_type >> P_OPCODE_SHIFT;

		//if(op==P_DATA_V1)
		//	return 1; //data pkt

		if(op==0)
			return 1; //data pkt

		if(op==P_DATA_V1)
			return 0; 
		
		if(op>=P_FIRST_OPCODE && op<=P_LAST_OPCODE)
		{
			if(op==P_CONTROL_HARD_RESET_SERVER_V2)
			{				
				vpn_shared_info.local_layer_hdr_len=net_hdr_len+1;
				vpn_shared_info.wan_dev=(void*)rtl_vpn_get_skb_dev(skb);
				
				vpn_shared_info.out_dev=rtl_vpn_get_dev_by_name("ppp0");
				
				printk("\n%s:%d vpn_shared_info.wan_dev NAME %s\n\n",__FUNCTION__,__LINE__, ((struct net_device *)(vpn_shared_info.wan_dev))->name);

				//vpn_shared_info.wan_dev=rtl_vpn_get_dev_by_name(ETH_IFNAME);

				peer_ip= *((uint32*)(data+38));
				peer_port= *((uint16*)(data+44));

				client_idx=lookup_client_by_ip_and_port(peer_ip, peer_port, ADD_CLIENT_FLAG);
				if(client_idx<0 || client_idx>=MAX_CLIENT_NUM)
				{
					printk("%s##Invalid Client Index!\n",__FUNCTION__);
					return 0;
				}	

				memset(vpn_client_info[client_idx].peer_layer_hdr, 0, net_hdr_len+1);					
				memcpy(vpn_client_info[client_idx].peer_layer_hdr, data, net_hdr_len+1);
				vpn_client_info[client_idx].pkt_id=1;	
				vpn_client_info[client_idx].key_info[KS_PRIMARY].key_id=0;
				vpn_client_info[client_idx].key_info[KS_LAME_DUCK].key_id=0;
				vpn_client_info[client_idx].active_flag=0;
				vpn_client_info[client_idx].soft_rest_flag=0;
				vpn_client_info[client_idx].enc_key_index=0;
				
				#if 0
				for(i=0;i<MAX_CLIENT_NUM;i++)
				if(vpn_client_info[i].peer_ip==peer_ip && vpn_client_info[i].peer_port==peer_port)
				{
					memset(vpn_client_info[i].peer_layer_hdr, 0, net_hdr_len+1);
					memcpy(vpn_client_info[i].peer_layer_hdr, data, net_hdr_len+1);
					vpn_client_info[i].pkt_id=0;
					vpn_client_info[i].key_info[KS_PRIMARY].key_id=0;
					vpn_client_info[i].key_info[KS_LAME_DUCK].key_id=0;
					vpn_client_info[i].active_flag=0;
					vpn_client_info[i].soft_rest_flag=0;
					break;
				}
				#endif
			}
			if(op==P_CONTROL_SOFT_RESET_V1)
			{
				//printk("\nSend Soft Reset Packet!\n");
				peer_ip= *((uint32*)(data+38));
				peer_port= *((uint16*)(data+44));

				for(i=0;i<MAX_CLIENT_NUM;i++)
				if(vpn_client_info[i].peer_ip==peer_ip && vpn_client_info[i].peer_port==peer_port)
				{	
					vpn_client_info[i].soft_rest_flag=1;
					break;
				}				
			}
			return 2; //ctrl pkt
		}
	}

	return 0;
}

int check_recv_pkt(struct sk_buff *skb, int *out_layer_hdr_len, int *dec_key_id, int flag)
{	
	u8 pkt_type;
	u8 op;

	int i;
	u32 peer_ip;
	u16 peer_port;

	int net_hdr_len;		
	unsigned char *data;
	//struct iphdr *iph;
	//struct udphdr *udph;	

	if(rtl_vpn_get_skb_len(skb)<MAX_OUT_LAYER_HDR_LEN)
		return 0;

	data = rtl_vpn_get_skb_data(skb);
	
	if(flag==1 && *((uint16*)(data+36))==vpn_shared_info.local_port)
	{
		net_hdr_len=ETH_HDR_HLEN+IP_HDR_LEN+UDP_HDR_LEN; 
		//printk("%s net_hdr_len=%d\n",__FUNCTION__,net_hdr_len);
		pkt_type=data[net_hdr_len];
		op=pkt_type >> P_OPCODE_SHIFT;

		if(op==P_DATA_V1)
		{
			*out_layer_hdr_len=net_hdr_len+1;
			*dec_key_id= pkt_type & P_KEY_ID_MASK;
			return 1; //data pkt
		}

		if(op>=P_FIRST_OPCODE && op<=P_LAST_OPCODE)
		{
			if(op==P_CONTROL_HARD_RESET_CLIENT_V2)
			{
				peer_ip= *((uint32*)(data+26));
				peer_port= *((uint16*)(data+34));				
				
				for(i=0;i<MAX_CLIENT_NUM;i++)
				if(vpn_client_info[i].peer_ip==peer_ip && vpn_client_info[i].peer_port==peer_port)
				{
					vpn_client_info[i].pkt_id=0;					
					//vpn_client_info[i].key_id=0;
					vpn_client_info[i].active_flag=0;
					break;
				}
			}
			if(op==P_CONTROL_SOFT_RESET_V1)
			{
				//printk("\Receive Soft Reset Packet!\n");
				peer_ip= *((uint32*)(data+26));
				peer_port= *((uint16*)(data+34));

				for(i=0;i<MAX_CLIENT_NUM;i++)
				if(vpn_client_info[i].peer_ip==peer_ip && vpn_client_info[i].peer_port==peer_port)
				{									
					vpn_client_info[i].soft_rest_flag=1;
					break;
				}				
			}
			return 2;  //ctrl pkt
		}
		/*
		if(op>=P_FIRST_OPCODE && op<=P_LAST_OPCODE)
		{			
			return 2; //ctrl pkt
		}*/
	}
	
	if(flag==2 && *((uint16*)(data+44))==vpn_shared_info.local_port)
	{
		net_hdr_len=ETH_HDR_HLEN+PPP_HDR_LEN+IP_HDR_LEN+UDP_HDR_LEN; 
		pkt_type=data[net_hdr_len];
		op=pkt_type >> P_OPCODE_SHIFT;

		if(op==P_DATA_V1)
		{
			*out_layer_hdr_len=net_hdr_len+1;
			*dec_key_id= pkt_type & P_KEY_ID_MASK;
			return 1; //data pkt
		}

		if(op>=P_FIRST_OPCODE && op<=P_LAST_OPCODE)
		{
			if(op==P_CONTROL_HARD_RESET_CLIENT_V2)
			{
				peer_ip= *((uint32*)(data+34));
				peer_port= *((uint16*)(data+42));				
				
				for(i=0;i<MAX_CLIENT_NUM;i++)
				if(vpn_client_info[i].peer_ip==peer_ip && vpn_client_info[i].peer_port==peer_port)
				{
					vpn_client_info[i].pkt_id=0;					
					//vpn_client_info[i].key_id=0;
					vpn_client_info[i].active_flag=0;
					break;
				}
			}
			if(op==P_CONTROL_SOFT_RESET_V1)
			{
				//printk("\Receive Soft Reset Packet!\n");
				peer_ip= *((uint32*)(data+34));
				peer_port= *((uint16*)(data+42));

				for(i=0;i<MAX_CLIENT_NUM;i++)
				if(vpn_client_info[i].peer_ip==peer_ip && vpn_client_info[i].peer_port==peer_port)
				{									
					vpn_client_info[i].soft_rest_flag=1;
					break;
				}				
			}
			return 2;  //ctrl pkt
		}
		/*
		if(op>=P_FIRST_OPCODE && op<=P_LAST_OPCODE)
		{			
			return 2; //ctrl pkt
		}*/
	}

	return 0;
}

int rtk_openvpn_hw_encrypto(struct sk_buff *skb, int flag)
{
	u32 peer_ip, cur_pkt_id;
	u16 peer_port;
	int len, err, client_idx, ret_val;
	rtl_ipsecScatter_t scatter[1];
	unsigned char *data;
	//struct iphdr *iph;
	//struct udphdr *udph;
	int enc_key_id=0;
	int key_index=0;

	SMP_LOCK_IPSEC;
	
	ret_val=check_send_pkt(skb, flag);
	//if(ret_val==1 || ret_val==2)		
	//	mod_timer(&(vpn_client_info[client_idx].ping_send_timer), jiffies+RTL_SECONDS_TO_JIFFIES(vpn_shared_info.ping_send_time));

	if(ret_val != 1)
	{
		//printk("%s This packet is not vpn data packet!\n\n",__FUNCTION__);	
		SMP_UNLOCK_IPSEC;
		return 0;
	}

	//printk("%s This packet is vpn data packet!\n\n",__FUNCTION__);

	data = rtl_vpn_get_skb_data(skb);

	//if(*((uint16*)(data+12))==htons(0x8864))
	//	iph=(struct iphdr *)(data+ETH_HDR_HLEN+PPP_HDR_LEN);
	//else 
	//	iph=(struct iphdr *)(data+ETH_HDR_HLEN);	
	
	//udph=(struct udphdr *)(((unsigned char *)iph) + iph->ihl*4);		

	peer_ip=  *((uint32*)(data+vpn_shared_info.local_layer_hdr_len-13));
	peer_port= *((uint16*)(data+vpn_shared_info.local_layer_hdr_len-7));
	//printk("%s peer_ip=%04x peer_port=%d\n",__FUNCTION__,peer_ip,peer_port);

	for(client_idx=0;client_idx<MAX_CLIENT_NUM;client_idx++)
	if(vpn_client_info[client_idx].active_flag>0 && vpn_client_info[client_idx].peer_ip==peer_ip && vpn_client_info[client_idx].peer_port==peer_port)
		break;

	//printk("\n%s client_idx=%d\n",__FUNCTION__,client_idx);
	
	if(client_idx==MAX_CLIENT_NUM)
	{
		printk("%s client_idx=%d\n\n",__FUNCTION__,client_idx);	
		SMP_UNLOCK_IPSEC;
		return -1;
	}

	//SMP_LOCK_IPSEC;

	//WRITE_MEM32( IPSCTR, READ_MEM32(IPSCTR)|IPS_SAWB);
	
	key_index=vpn_client_info[client_idx].enc_key_index;
	enc_key_id=vpn_client_info[client_idx].key_info[key_index].key_id;

	//printk("\n%s key_index=%d enc_key_id=%d\n",__FUNCTION__,key_index,enc_key_id);
	
	mod_timer(&(vpn_client_info[client_idx].ping_send_timer), jiffies+RTL_SECONDS_TO_JIFFIES(vpn_shared_info.ping_send_time));

	//if(memcmp(vpn_client_info[client_idx].peer_layer_hdr, EMPTY_MAC_ADDR, 6)==0)
	//	memcpy(vpn_client_info[client_idx].peer_layer_hdr, skb->data, vpn_shared_info.local_layer_hdr_len);
		
	//printk("%s client_idx=%d\n\n",__FUNCTION__,client_idx);
	
	//len=skb->len-vpn_shared_info.local_layer_hdr_len-vpn_shared_info.digest_len-IV_LEN;

	//GenerateRandomData(vpn_client_info[client_idx].key_info[key_index].iv, IV_LEN);

	//increaseVI(vpn_client_info[client_idx].key_info[key_index].iv, 1);
	
	len=rtl_vpn_get_skb_len(skb)-vpn_shared_info.local_layer_hdr_len-vpn_shared_info.digest_len-IV_LEN;
	memcpy(vpn_shared_info.enc_data+vpn_shared_info.digest_len, vpn_client_info[client_idx].key_info[key_index].iv, IV_LEN);
	memcpy(vpn_shared_info.enc_data+vpn_shared_info.digest_len+IV_LEN, data+vpn_shared_info.local_layer_hdr_len+vpn_shared_info.digest_len+IV_LEN, len);

#if 0
	#if 1
	cur_pkt_id=*((u32 *)(vpn_shared_info.enc_data+vpn_shared_info.digest_len+IV_LEN));

	if(cur_pkt_id==0 && vpn_client_info[client_idx].pkt_id==0)
		vpn_client_info[client_idx].pkt_id=1;	

	//printk("\nvpn_client_info[%d].pkt_id=%d cur_pkt_id=%d\n",client_idx,vpn_client_info[client_idx].pkt_id,cur_pkt_id);

	if(vpn_client_info[client_idx].pkt_id>cur_pkt_id)
		*((u32 *)(vpn_shared_info.enc_data+vpn_shared_info.digest_len+IV_LEN))=vpn_client_info[client_idx].pkt_id;
	else 
		vpn_client_info[client_idx].pkt_id=cur_pkt_id;
	#endif
	
	//*((u32 *)(vpn_shared_info.enc_data+vpn_shared_info.digest_len+IV_LEN))=vpn_client_info[client_idx].pkt_id;
	
	vpn_client_info[client_idx].pkt_id++;
	
	if(vpn_client_info[client_idx].pkt_id > MAX_PKT_ID)
	{
		printk("\n%s The client %d packet id > %ld !!!\n",__FUNCTION__,client_idx,MAX_PKT_ID);
		vpn_client_info[client_idx].pkt_id=1;
	}
#endif

	//printk("\nvpn_client_info[%d].pkt_id=%08x\n", client_idx, vpn_client_info[client_idx].pkt_id);

	if(vpn_shared_info.auth_none==1)
	{
		scatter[0].len = len;
		scatter[0].ptr = (void *) CKSEG1ADDR(vpn_shared_info.enc_data+vpn_shared_info.digest_len+IV_LEN);	

		err=rtl_ipsecEngine(ENCRYPT_CBC_AES, _MD_NOAUTH,
    		1, scatter, vpn_shared_info.CryptResult,
    		vpn_client_info[client_idx].crypt_key_len, vpn_client_info[client_idx].key_info[key_index].enc_key,
    		0, NULL,
    		vpn_client_info[client_idx].key_info[key_index].iv, NULL, NULL,
    		0, len);
	}
	else
	{
		scatter[0].len = IV_LEN+len;
    		scatter[0].ptr = (void *) CKSEG1ADDR(vpn_shared_info.enc_data+vpn_shared_info.digest_len);

		err=rtl_ipsecEngine(ENCRYPT_CBC_AES | 0x04, HMAC_SHA1,
		1, scatter, vpn_shared_info.CryptResult,
		//1, scatter, NULL,
		vpn_client_info[client_idx].crypt_key_len, vpn_client_info[client_idx].key_info[key_index].enc_key,
		vpn_client_info[client_idx].hmac_key_len, vpn_client_info[client_idx].key_info[key_index].enc_hmac_key,
		vpn_client_info[client_idx].key_info[key_index].iv, NULL, vpn_shared_info.enc_data,
		IV_LEN, len);
	}	

	//SMP_UNLOCK_IPSEC;

	if (unlikely(err))
	{
		printk("%s:%d rtl_ipsecEngine failed!!! re-init crypto engine!!!\n", __FUNCTION__,__LINE__);
		SMP_UNLOCK_IPSEC;
		
		rtl_ipsecEngine_init(DEFAULT_DESC_NUM, 2);
		//rtl_ipsecSetOption(RTL_IPSOPT_SAWB, 1);
		return -1;
	}
	else
	{		
		//count_call_hw_engine++;
		
		data[vpn_shared_info.local_layer_hdr_len-1]=((P_DATA_V1<<P_OPCODE_SHIFT) | enc_key_id); 
		memcpy(data+vpn_shared_info.local_layer_hdr_len, vpn_shared_info.enc_data, vpn_shared_info.digest_len+IV_LEN+len);

		*((u16*)(data+vpn_shared_info.local_layer_hdr_len-25))=htons(vpn_shared_info.ip_id);
		vpn_shared_info.ip_id++;
		if(vpn_shared_info.ip_id>65535)
		{
			//printk("\n%s OpenVPN ip header ID:%d\n",__FUNCTION__,vpn_shared_info.ip_id);
			vpn_shared_info.ip_id=1;
		}
		
		SMP_UNLOCK_IPSEC;
		//printk("OpenVPN ENC RESULT:\n\n");
		//dump_openvpn_info(vpn_data+vpn_shared_info.digest_len+IV_LEN, vpn_data_len+CBC_BLOCK_SIZE, 4);				
	}	

	//data[vpn_shared_info.local_layer_hdr_len-1]=((P_DATA_V1<<P_OPCODE_SHIFT) | enc_key_id); 
	//memcpy(data+vpn_shared_info.local_layer_hdr_len, vpn_shared_info.enc_data, vpn_shared_info.digest_len+IV_LEN+len);

	*((u16*)(data+vpn_shared_info.local_layer_hdr_len-23))=0;
	
	//*((u16*)(data+vpn_shared_info.local_layer_hdr_len-25))=vpn_shared_info.ip_id;

	//ip_select_ident(skb, &rt->dst, NULL);

	////////////////only for litter endian 
	u16 tmp_udp_len=*((u16*)(data+vpn_shared_info.local_layer_hdr_len-5));
	*((u16*)(data+vpn_shared_info.local_layer_hdr_len-5))=htons(tmp_udp_len);

	u16 tmp_ip_len=*((u16*)(data+vpn_shared_info.local_layer_hdr_len-27));
	*((u16*)(data+vpn_shared_info.local_layer_hdr_len-27))=htons(tmp_ip_len);

	if(vpn_shared_info.local_layer_hdr_len==MAX_OUT_LAYER_HDR_LEN)
	{		
		*((u16*)(data+ETH_HDR_HLEN+4))=htons(rtl_vpn_get_skb_len(skb)-IP_HDR_LEN);
	}
	//////////////////////////////////	
	
	*((u16*)(data+vpn_shared_info.local_layer_hdr_len-19))=0;	
	*((u16*)(data+vpn_shared_info.local_layer_hdr_len-19))=ip_fast_csum((u8*)(data+vpn_shared_info.local_layer_hdr_len-29), 5);
	//iph->check=ip_fast_csum((unsigned char *)iph, iph->ihl);

	*((u16*)(data+vpn_shared_info.local_layer_hdr_len-3))=0;	

	

#if 0
	if(count_call_hw_engine % LIMIT_HW_ENGINE_NUM ==0)
	{		
		printk("%s:%d count_call_hw_engine=%u re-init crypto engine!!!\n", __FUNCTION__,__LINE__,count_call_hw_engine);
		rtl_ipsecEngine_init(10, 2);
	}
#endif

	return 0;
	//udph->check=0;
}

int openvpn_fragment_fast_to_wan(struct sk_buff *skb)
{
	u32 peer_ip, cur_pkt_id;
	u16 peer_port;
	int len, err, client_idx, ret_val;
	rtl_ipsecScatter_t scatter[1];
	unsigned char *data;
	//struct iphdr *iph;
	//struct udphdr *udph;
	int enc_key_id=0;
	int key_index=0;
	int header_len=0, ppp_hdr_len=0;

	//SMP_LOCK_IPSEC;	

	data = rtl_vpn_get_skb_data(skb);			

	peer_ip= *((uint32*)(data+16));
	//peer_port= *((uint16*)(data+22));
	
	//printk("\n %s peer_ip=%04x peer_port=%d\n",__FUNCTION__,peer_ip,peer_port);

	for(client_idx=0;client_idx<MAX_CLIENT_NUM;client_idx++)
	//if(vpn_client_info[client_idx].active_flag>0 && vpn_client_info[client_idx].peer_ip==peer_ip && vpn_client_info[client_idx].peer_port==peer_port)
	
	if(vpn_client_info[client_idx].active_flag>0 && vpn_client_info[client_idx].peer_ip==peer_ip)
		break;

	//printk("\n%s client_idx=%d\n",__FUNCTION__,client_idx);
	
	if(client_idx==MAX_CLIENT_NUM)
	{
		printk("%s client_idx=%d\n\n",__FUNCTION__,client_idx);	
		//SMP_UNLOCK_IPSEC;
		return 1;
	}

	if(vpn_shared_info.local_layer_hdr_len==MAX_OUT_LAYER_HDR_LEN)
	 {	 
		ppp_hdr_len=PPP_HDR_LEN;
	 }	
	
	header_len = ETH_HDR_HLEN+ppp_hdr_len;
	
	if (rtl_vpn_skb_headroom(skb) < header_len || rtl_vpn_skb_cloned(skb) || rtl_vpn_skb_shared(skb))
	{
		void *new_skb = (void*)skb_realloc_headroom(skb, header_len);
		if (!new_skb) 
		{
			printk("%s: skb_realloc_headroom failed!\n", __FUNCTION__);
			return 0;
		}
		dev_kfree_skb(skb);
		skb = new_skb;
	}

	rtl_vpn_skb_push(skb, header_len);	

	data = rtl_vpn_get_skb_data(skb);
	
	memcpy(data, vpn_client_info[client_idx].peer_layer_hdr, header_len);

	if(vpn_shared_info.local_layer_hdr_len==MAX_OUT_LAYER_HDR_LEN)
		*((u16*)(data+ETH_HDR_HLEN+4))=htons(rtl_vpn_get_skb_len(skb)-IP_HDR_LEN);	
	
	rtl_vpn_set_skb_dev(skb, vpn_shared_info.wan_dev);	 	

	rtl_vpn_call_skb_ndo_start_xmit(skb);

	//tun_dev->stats.tx_packets++;
	//tun_dev->stats.tx_bytes += orig_len;
	return 0;
}
EXPORT_SYMBOL(openvpn_fragment_fast_to_wan);

#if 0
int rtk_openvpn_fragment_hw_encrypto(struct sk_buff *skb)
{
	u32 header_len, padding_len, peer_virtual_ip;
	int i, orig_len, client_idx;
	unsigned char *data;
	//struct iphdr *iph;
	//struct udphdr *udph;
	//struct tun_struct *tun;
	struct net_device	*tun_dev;
	int len, err, ret_val;
	rtl_ipsecScatter_t scatter[1];
	
	int enc_key_id=0;
	int key_index=0;
	int ppp_hdr_len=0;
	struct net_device	*out_dev=NULL;	
	
	if(vpn_shared_info.wan_dev==NULL)
		return -1;	
	//else
	//	printk("\n%s vpn_shared_info.wan_dev NAME %s\n\n",__FUNCTION__,((struct net_device *)(vpn_shared_info.wan_dev))->name);


	SMP_LOCK_IPSEC;
	
	if(vpn_shared_info.tun_dev==NULL)
		vpn_shared_info.tun_dev=rtl_vpn_get_skb_dev(skb);

	tun_dev=(struct net_device *)vpn_shared_info.tun_dev;	
	
	//printk("%s TUN NAME %s\n\n",__FUNCTION__,((struct net_device *)(vpn_shared_info.tun_dev))->name);

	//skb_linearize(skb);
	
	data = rtl_vpn_get_skb_data(skb);
	//iph=(struct iphdr *)data;
	//udph=(struct udphdr *)(((unsigned char *)iph) + iph->ihl*4);
	
	peer_virtual_ip=*((uint32*)(data+16));
	//peer_virtual_ip=iph->daddr;	
	//printk("\n%s peer_virtual_ip=%04x\n",__FUNCTION__,peer_virtual_ip);

	//SMP_LOCK_IPSEC;
	
	for(client_idx=0;client_idx<MAX_CLIENT_NUM;client_idx++)
	if(vpn_client_info[client_idx].active_flag>0 && vpn_client_info[client_idx].virtual_ip==peer_virtual_ip)
		break;

	//printk("\n%s client_idx=%d\n",__FUNCTION__,client_idx);

	if(client_idx==MAX_CLIENT_NUM)
	{
		//printk("%s client_idx=%d\n\n",__FUNCTION__,client_idx);
		SMP_UNLOCK_IPSEC;
		return -1;	
	}

	if(memcmp(vpn_client_info[client_idx].peer_layer_hdr, EMPTY_MAC_ADDR, 6)==0)
	{
		SMP_UNLOCK_IPSEC;
		return -1;
	}
	else
	{
		//printk("%s CLIENT %d layer header len %d:\n", __FUNCTION__, client_idx, vpn_shared_info.local_layer_hdr_len);
		//dump_openvpn_info(vpn_client_info[client_idx].peer_layer_hdr, vpn_shared_info.local_layer_hdr_len, 4);
	}

	//printk("%s client_idx=%d\n\n",__FUNCTION__,client_idx);

	key_index=vpn_client_info[client_idx].enc_key_index;
	enc_key_id=vpn_client_info[client_idx].key_info[key_index].key_id;

	//padding
	orig_len=rtl_vpn_get_skb_len(skb);
	//printk("\n%s orig_len=%d\n",__FUNCTION__,orig_len);
	padding_len=CBC_BLOCK_SIZE-(orig_len+PKT_ID_LEN)%CBC_BLOCK_SIZE;
	//printk("\n%s padding_len=%d\n",__FUNCTION__,padding_len);
	
	rtl_vpn_skb_put(skb, padding_len);	
	
	 for(i=0; i<padding_len; i++)
		data[orig_len+i]=padding_len;	

	 if(vpn_shared_info.local_layer_hdr_len==MAX_OUT_LAYER_HDR_LEN)
	 {	 
		ppp_hdr_len=PPP_HDR_LEN;
	 }	 


	tun_dev->stats.tx_packets++;
	tun_dev->stats.tx_bytes += orig_len;
	
	 out_dev=(struct net_device *)vpn_shared_info.out_dev;
	
	header_len = FRAGMENT_OUT_LAYER_HDR_LEN+vpn_shared_info.digest_len+IV_LEN+PKT_ID_LEN;
	if (rtl_vpn_skb_headroom(skb) < header_len || rtl_vpn_skb_cloned(skb) || rtl_vpn_skb_shared(skb))
	{
		void *new_skb = (void*)skb_realloc_headroom(skb, header_len);
		if (!new_skb) 
		{
			printk("%s: skb_realloc_headroom failed!\n", __FUNCTION__);
			SMP_UNLOCK_IPSEC;
			return -1;
		}
		//printk("\n#########%s:%d##########calling dev_kfree_skb()!!!!\n",__FUNCTION__,__LINE__);
		dev_kfree_skb(skb);
		skb = new_skb;

		//skb_reserve(*skb, 2);
	}

	rtl_vpn_skb_push(skb, header_len);	
	data = rtl_vpn_get_skb_data(skb);	
	
	memcpy(data, vpn_client_info[client_idx].peer_layer_hdr+ETH_HDR_HLEN+ppp_hdr_len, FRAGMENT_OUT_LAYER_HDR_LEN);
	
	*((u32 *)(data+header_len-PKT_ID_LEN))=vpn_client_info[client_idx].pkt_id;

	vpn_client_info[client_idx].pkt_id++;		
	if(vpn_client_info[client_idx].pkt_id > MAX_PKT_ID)
	{
		printk("\n%s The client %d packet id > %ld !!!\n",__FUNCTION__,client_idx,MAX_PKT_ID);
		vpn_client_info[client_idx].pkt_id=1;
	}
			
	*((u8 *)(data+header_len-1))=0xfa;	
	*((u8 *)(data+FRAGMENT_OUT_LAYER_HDR_LEN-1))=((P_DATA_V1<<P_OPCODE_SHIFT) | enc_key_id);	

	*((u16*)(data+24))=rtl_vpn_get_skb_len(skb)-IP_HDR_LEN;
	//udph->len=rtl_vpn_get_skb_len(skb)-vpn_shared_info.local_layer_hdr_len+1+UDP_HDR_LEN;
	*((u16*)(data+2))=rtl_vpn_get_skb_len(skb);
	//iph->tot_len=rtl_vpn_get_skb_len(skb)-vpn_shared_info.local_layer_hdr_len+1+UDP_HDR_LEN+iph->ihl*4;	

	//printk("\n%s:%d (*skb)->len=%d!!!! out_dev->mtu=%d\n",__FUNCTION__,__LINE__,(*skb)->len,out_dev->mtu);
	
	//if((*skb)->len>out_dev->mtu)
	{	
		//SMP_LOCK_IPSEC;
		//WRITE_MEM32( IPSCTR, READ_MEM32(IPSCTR)|IPS_SAWB);
		
		mod_timer(&(vpn_client_info[client_idx].ping_send_timer), jiffies+RTL_SECONDS_TO_JIFFIES(vpn_shared_info.ping_send_time));

		len=rtl_vpn_get_skb_len(skb)-FRAGMENT_OUT_LAYER_HDR_LEN-vpn_shared_info.digest_len-IV_LEN;
		memcpy(vpn_shared_info.enc_data+vpn_shared_info.digest_len, vpn_client_info[client_idx].key_info[key_index].iv, IV_LEN);
		memcpy(vpn_shared_info.enc_data+vpn_shared_info.digest_len+IV_LEN, data+FRAGMENT_OUT_LAYER_HDR_LEN+vpn_shared_info.digest_len+IV_LEN, len);	
		

		//printk("\n%s key_index=%d enc_key_id=%d\n",__FUNCTION__,key_index,enc_key_id);
		//printk("\nvpn_client_info[%d].pkt_id=%08x\n", client_idx, vpn_client_info[client_idx].pkt_id);

		scatter[0].len = IV_LEN+len;
		scatter[0].ptr = (void *) CKSEG1ADDR(vpn_shared_info.enc_data+vpn_shared_info.digest_len);		

		err=rtl_ipsecEngine(ENCRYPT_CBC_AES | 0x04, HMAC_SHA1, 
		1, scatter, vpn_shared_info.CryptResult,
		//1, scatter, NULL,
		vpn_client_info[client_idx].crypt_key_len, vpn_client_info[client_idx].key_info[key_index].enc_key, 
		vpn_client_info[client_idx].hmac_key_len, vpn_client_info[client_idx].key_info[key_index].enc_hmac_key, 				
		vpn_client_info[client_idx].key_info[key_index].iv, NULL, vpn_shared_info.enc_data,
		IV_LEN, len);

		//SMP_UNLOCK_IPSEC;

		if (unlikely(err))
		{
			printk("%s:%d rtl_ipsecEngine failed!!! re-init crypto engine!!!\n", __FUNCTION__,__LINE__);
			SMP_UNLOCK_IPSEC;
			
			rtl_ipsecEngine_init(10, 2);
			rtl_ipsecSetOption(RTL_IPSOPT_SAWB, 1);
			return -1;
		}
		else
		{		
			//printk("OpenVPN ENC RESULT:\n\n");
			//dump_openvpn_info(vpn_data+vpn_shared_info.digest_len+IV_LEN, vpn_data_len+CBC_BLOCK_SIZE, 4);				

			memcpy(data+FRAGMENT_OUT_LAYER_HDR_LEN, vpn_shared_info.enc_data, vpn_shared_info.digest_len+IV_LEN+len);
			SMP_UNLOCK_IPSEC;
		}	

		//memcpy(data+FRAGMENT_OUT_LAYER_HDR_LEN, vpn_shared_info.enc_data, vpn_shared_info.digest_len+IV_LEN+len);
		//SMP_UNLOCK_IPSEC;
	}
	
	//SMP_UNLOCK_IPSEC;

	//*((u16*)(data+4))=0;
	*((u16*)(data+6))=0;	
	*((u16*)(data+10))=0;	
	*((u16*)(data+10))=ip_fast_csum((u8*)data, 5);
	//iph->check=ip_fast_csum((unsigned char *)iph, iph->ihl);

	*((u16*)(data+26))=0;	

	//dump_openvpn_info((*skb)->data, FRAGMENT_OUT_LAYER_HDR_LEN, 1);

	skb_set_network_header(skb, 0);			//set ip header
	//skb_set_transport_header(*skb, IP_HDR_LEN);

	 if(vpn_shared_info.local_layer_hdr_len==MAX_OUT_LAYER_HDR_LEN)
	 	rtl_vpn_set_skb_dev(skb, out_dev);
	 else
		rtl_vpn_set_skb_dev(skb, vpn_shared_info.wan_dev);

	 return 0;
	
	//printk("\n%s:%d end!!!skb->dev->name=%s skb->len=%d data_addr=%p\n",__FUNCTION__,__LINE__,(*skb)->dev->name, (*skb)->len,(*skb)->data);
	//udph->check=0;
}
EXPORT_SYMBOL(rtk_openvpn_fragment_hw_encrypto);
#endif


#if 1
int rtk_openvpn_fragment_hw_encrypto(struct sk_buff **skb)
{
	u32 header_len, padding_len, peer_virtual_ip;
	int i, orig_len, client_idx;
	unsigned char *data;
	//struct iphdr *iph;
	//struct udphdr *udph;
	//struct tun_struct *tun;
	struct net_device	*tun_dev;
	int len, err, ret_val;
	rtl_ipsecScatter_t scatter[1];
	
	int enc_key_id=0;
	int key_index=0;
	int ppp_hdr_len=0;
	struct net_device	*out_dev=NULL;	
	
	if(vpn_shared_info.wan_dev==NULL)
		return -1;	
	//else
	//	printk("\n%s vpn_shared_info.wan_dev NAME %s\n\n",__FUNCTION__,((struct net_device *)(vpn_shared_info.wan_dev))->name);


	SMP_LOCK_IPSEC;
	
	if(vpn_shared_info.tun_dev==NULL)
		vpn_shared_info.tun_dev=rtl_vpn_get_skb_dev(*skb);

	tun_dev=(struct net_device *)vpn_shared_info.tun_dev;	
	
	//printk("%s TUN NAME %s\n\n",__FUNCTION__,((struct net_device *)(vpn_shared_info.tun_dev))->name);

	skb_linearize(*skb);
	
	data = rtl_vpn_get_skb_data(*skb);
	//iph=(struct iphdr *)data;
	//udph=(struct udphdr *)(((unsigned char *)iph) + iph->ihl*4);
	
	peer_virtual_ip=*((uint32*)(data+16));
	//peer_virtual_ip=iph->daddr;	
	//printk("\n%s peer_virtual_ip=%04x\n",__FUNCTION__,peer_virtual_ip);

	//SMP_LOCK_IPSEC;
	
	for(client_idx=0;client_idx<MAX_CLIENT_NUM;client_idx++)
	if(vpn_client_info[client_idx].active_flag>0 && vpn_client_info[client_idx].virtual_ip==peer_virtual_ip)
		break;

	//printk("\n%s client_idx=%d\n",__FUNCTION__,client_idx);

	if(client_idx==MAX_CLIENT_NUM)
	{
		//printk("%s client_idx=%d\n\n",__FUNCTION__,client_idx);
		SMP_UNLOCK_IPSEC;
		return -1;	
	}

	if(memcmp(vpn_client_info[client_idx].peer_layer_hdr, EMPTY_MAC_ADDR, 6)==0)
	{
		SMP_UNLOCK_IPSEC;
		return -1;
	}
	else
	{
		//printk("%s CLIENT %d layer header len %d:\n", __FUNCTION__, client_idx, vpn_shared_info.local_layer_hdr_len);
		//dump_openvpn_info(vpn_client_info[client_idx].peer_layer_hdr, vpn_shared_info.local_layer_hdr_len, 4);
	}

	//printk("%s client_idx=%d\n\n",__FUNCTION__,client_idx);

	key_index=vpn_client_info[client_idx].enc_key_index;
	enc_key_id=vpn_client_info[client_idx].key_info[key_index].key_id;

	//padding
	orig_len=rtl_vpn_get_skb_len(*skb);
	//printk("\n%s orig_len=%d\n",__FUNCTION__,orig_len);
	padding_len=CBC_BLOCK_SIZE-(orig_len+PKT_ID_LEN)%CBC_BLOCK_SIZE;
	//printk("\n%s padding_len=%d\n",__FUNCTION__,padding_len);
	
	rtl_vpn_skb_put(*skb, padding_len);	
	
	 for(i=0; i<padding_len; i++)
		data[orig_len+i]=padding_len;	

	 if(vpn_shared_info.local_layer_hdr_len==MAX_OUT_LAYER_HDR_LEN)
	 {	 
		ppp_hdr_len=PPP_HDR_LEN;
	 }	 


	tun_dev->stats.tx_packets++;
	tun_dev->stats.tx_bytes += orig_len;
	
	 out_dev=(struct net_device *)vpn_shared_info.out_dev;
	
	header_len = FRAGMENT_OUT_LAYER_HDR_LEN+vpn_shared_info.digest_len+IV_LEN+PKT_ID_LEN;
	if (rtl_vpn_skb_headroom(*skb) < header_len || rtl_vpn_skb_cloned(*skb) || rtl_vpn_skb_shared(*skb))
	{
		void *new_skb = (void*)skb_realloc_headroom(*skb, header_len);
		if (!new_skb) 
		{
			printk("%s: skb_realloc_headroom failed!\n", __FUNCTION__);
			SMP_UNLOCK_IPSEC;
			return -1;
		}
		//printk("\n#########%s:%d##########calling dev_kfree_skb()!!!!\n",__FUNCTION__,__LINE__);
		dev_kfree_skb(*skb);
		*skb = new_skb;

		//skb_reserve(*skb, 2);
	}

	rtl_vpn_skb_push(*skb, header_len);	
	data = rtl_vpn_get_skb_data(*skb);	
	
	memcpy(data, vpn_client_info[client_idx].peer_layer_hdr+ETH_HDR_HLEN+ppp_hdr_len, FRAGMENT_OUT_LAYER_HDR_LEN);


#if 0
	*((u32 *)(data+header_len-PKT_ID_LEN))=vpn_client_info[client_idx].pkt_id;

	vpn_client_info[client_idx].pkt_id++;		
	if(vpn_client_info[client_idx].pkt_id > MAX_PKT_ID)
	{
		printk("\n%s The client %d packet id > %ld !!!\n",__FUNCTION__,client_idx,MAX_PKT_ID);
		vpn_client_info[client_idx].pkt_id=1;
	}
#endif
			
	*((u8 *)(data+header_len-1))=0xfa;	
	*((u8 *)(data+FRAGMENT_OUT_LAYER_HDR_LEN-1))=((P_DATA_V1<<P_OPCODE_SHIFT) | enc_key_id);	

	*((u16*)(data+24))=htons(rtl_vpn_get_skb_len(*skb)-IP_HDR_LEN);
	//udph->len=rtl_vpn_get_skb_len(skb)-vpn_shared_info.local_layer_hdr_len+1+UDP_HDR_LEN;
	*((u16*)(data+2))=htons(rtl_vpn_get_skb_len(*skb));
	//iph->tot_len=rtl_vpn_get_skb_len(skb)-vpn_shared_info.local_layer_hdr_len+1+UDP_HDR_LEN+iph->ihl*4;	

	//printk("\n%s:%d (*skb)->len=%d!!!! out_dev->mtu=%d\n",__FUNCTION__,__LINE__,(*skb)->len,out_dev->mtu);
	
	//if((*skb)->len>out_dev->mtu)
	{	
		//SMP_LOCK_IPSEC;
		//WRITE_MEM32( IPSCTR, READ_MEM32(IPSCTR)|IPS_SAWB);
		
		mod_timer(&(vpn_client_info[client_idx].ping_send_timer), jiffies+RTL_SECONDS_TO_JIFFIES(vpn_shared_info.ping_send_time));

		
		//GenerateRandomData(vpn_client_info[client_idx].key_info[key_index].iv, IV_LEN);

		//increaseVI(vpn_client_info[client_idx].key_info[key_index].iv, 1);
		
		len=rtl_vpn_get_skb_len(*skb)-FRAGMENT_OUT_LAYER_HDR_LEN-vpn_shared_info.digest_len-IV_LEN;
		memcpy(vpn_shared_info.enc_data+vpn_shared_info.digest_len, vpn_client_info[client_idx].key_info[key_index].iv, IV_LEN);
		memcpy(vpn_shared_info.enc_data+vpn_shared_info.digest_len+IV_LEN, data+FRAGMENT_OUT_LAYER_HDR_LEN+vpn_shared_info.digest_len+IV_LEN, len);	
		

		//printk("\n%s key_index=%d enc_key_id=%d\n",__FUNCTION__,key_index,enc_key_id);
		//printk("\nvpn_client_info[%d].pkt_id=%08x\n", client_idx, vpn_client_info[client_idx].pkt_id);

		if(vpn_shared_info.auth_none==1)
		{
			scatter[0].len = len;
			scatter[0].ptr = (void *) CKSEG1ADDR(vpn_shared_info.enc_data+vpn_shared_info.digest_len+IV_LEN);		

			err=rtl_ipsecEngine(ENCRYPT_CBC_AES, _MD_NOAUTH,
			1, scatter, vpn_shared_info.CryptResult,
			vpn_client_info[client_idx].crypt_key_len, vpn_client_info[client_idx].key_info[key_index].enc_key,
			0, NULL,
			vpn_client_info[client_idx].key_info[key_index].iv, NULL, NULL,
			0, len);
		}
		else
		{
			scatter[0].len = IV_LEN+len;
        		scatter[0].ptr = (void *) CKSEG1ADDR(vpn_shared_info.enc_data+vpn_shared_info.digest_len);

			err=rtl_ipsecEngine(ENCRYPT_CBC_AES | 0x04, HMAC_SHA1,
        		1, scatter, vpn_shared_info.CryptResult,
        		//1, scatter, NULL,
        		vpn_client_info[client_idx].crypt_key_len, vpn_client_info[client_idx].key_info[key_index].enc_key,
        		vpn_client_info[client_idx].hmac_key_len, vpn_client_info[client_idx].key_info[key_index].enc_hmac_key,
        		vpn_client_info[client_idx].key_info[key_index].iv, NULL, vpn_shared_info.enc_data,
        		IV_LEN, len);
		}

		//SMP_UNLOCK_IPSEC;

		if (unlikely(err))
		{
			printk("%s:%d rtl_ipsecEngine failed!!! re-init crypto engine!!!\n", __FUNCTION__,__LINE__);
			SMP_UNLOCK_IPSEC;
			
			rtl_ipsecEngine_init(DEFAULT_DESC_NUM, 2);
			//rtl_ipsecSetOption(RTL_IPSOPT_SAWB, 1);
			return -1;
		}
		else
		{		
			//printk("OpenVPN ENC RESULT:\n\n");
			//dump_openvpn_info(vpn_data+vpn_shared_info.digest_len+IV_LEN, vpn_data_len+CBC_BLOCK_SIZE, 4);				

			memcpy(data+FRAGMENT_OUT_LAYER_HDR_LEN, vpn_shared_info.enc_data, vpn_shared_info.digest_len+IV_LEN+len);
			SMP_UNLOCK_IPSEC;
		}	

		//memcpy(data+FRAGMENT_OUT_LAYER_HDR_LEN, vpn_shared_info.enc_data, vpn_shared_info.digest_len+IV_LEN+len);
		//SMP_UNLOCK_IPSEC;
	}
	
	//SMP_UNLOCK_IPSEC;

	//*((u16*)(data+4))=0;
	*((u16*)(data+6))=0;	
	*((u16*)(data+10))=0;	
	*((u16*)(data+10))=ip_fast_csum((u8*)data, 5);
	//iph->check=ip_fast_csum((unsigned char *)iph, iph->ihl);

	*((u16*)(data+26))=0;	

	//dump_openvpn_info((*skb)->data, FRAGMENT_OUT_LAYER_HDR_LEN, 1);

	skb_set_network_header(*skb, 0);			//set ip header
	//skb_set_transport_header(*skb, IP_HDR_LEN);

	 if(vpn_shared_info.local_layer_hdr_len==MAX_OUT_LAYER_HDR_LEN)
	 	rtl_vpn_set_skb_dev(*skb, out_dev);
	 else
		rtl_vpn_set_skb_dev(*skb, vpn_shared_info.wan_dev);

	 return 0;
	
	//printk("\n%s:%d end!!!skb->dev->name=%s skb->len=%d data_addr=%p\n",__FUNCTION__,__LINE__,(*skb)->dev->name, (*skb)->len,(*skb)->data);
	//udph->check=0;
}
EXPORT_SYMBOL(rtk_openvpn_fragment_hw_encrypto);
#endif

int rtk_openvpn_hw_decrypto(struct sk_buff *skb, int flag)
{
	//recv data to encrypt
	//printk("NIC OpenVPN DATA TO ENCRYPT:\n");
	//dump_openvpn_info(skb->data+SKB_DATA_OFFSET, skb->data+SKB_DATA_OFFSET, 4);	
	
	u32 len, peer_ip;
	u16 peer_port;
	int err, i, padding_len, tmp_len, out_data_len, out_layer_hdr_len, client_idx;	
	rtl_ipsecScatter_t scatter[1];

	unsigned char *data;
	//struct iphdr *iph;
	//struct udphdr *udph;
	struct net_device	*tun_dev;
	int rx_byte=0, ret_val;
	int dec_key_id=0;
	int key_index=0;

	SMP_LOCK_IPSEC;
	ret_val=check_recv_pkt(skb, &out_layer_hdr_len, &dec_key_id, flag);
	//if(ret_val==1 || ret_val==2)
	//	mod_timer(&(vpn_client_info[client_idx].ping_rec_timer), jiffies+RTL_SECONDS_TO_JIFFIES(vpn_shared_info.ping_rec_time));
	if(ret_val!=1)
	{
		//printk("%s This packet is not vpn data packet!\n\n",__FUNCTION__);
		SMP_UNLOCK_IPSEC;
		return 1;	
	}

	//printk("\n%s out_layer_hdr_len=%d!\n\n",__FUNCTION__,out_layer_hdr_len);

	data = rtl_vpn_get_skb_data(skb);
	
	//if(*((uint16*)(data+12))==htons(0x8864))
	//	iph=(struct iphdr *)(data+ETH_HDR_HLEN+PPP_HDR_LEN);
	//else
	//	iph=(struct iphdr *)(data+ETH_HDR_HLEN);	
	
	//udph=(struct udphdr *)(((unsigned char *)iph) + iph->ihl*4);	

	peer_ip = *((uint32*)(data+out_layer_hdr_len-17));
	peer_port= *((uint16*)(data+out_layer_hdr_len-9));
	
	//printk("\n%s peer_ip=%04x peer_port=%d\n",__FUNCTION__,peer_ip,peer_port);
	
	for(client_idx=0;client_idx<MAX_CLIENT_NUM;client_idx++)
	if(vpn_client_info[client_idx].active_flag>0 && vpn_client_info[client_idx].peer_ip==peer_ip && vpn_client_info[client_idx].peer_port==peer_port)
		break;

	//printk("\n%s client_idx=%d\n",__FUNCTION__,client_idx);
	
	if(client_idx==MAX_CLIENT_NUM)
	{		
		printk("\n%s can't find client idx\n",__FUNCTION__);
		SMP_UNLOCK_IPSEC;
		return -1;
	}

	//SMP_LOCK_IPSEC;
	
	//WRITE_MEM32( IPSCTR, READ_MEM32(IPSCTR)|IPS_SAWB);
	
	mod_timer(&(vpn_client_info[client_idx].ping_rec_timer), jiffies+RTL_SECONDS_TO_JIFFIES(vpn_shared_info.ping_rec_time));

	if(vpn_client_info[client_idx].key_info[KS_PRIMARY].key_id==dec_key_id)
		key_index=KS_PRIMARY;
	else if(vpn_client_info[client_idx].key_info[KS_LAME_DUCK].key_id==dec_key_id)
		key_index=KS_LAME_DUCK;
	else
	{		
		printk("\n%s key_info[KS_PRIMARY].key_id=%d  key_info[KS_LAME_DUCK].key_id=%d  dec_key_id=%d\n",__FUNCTION__,vpn_client_info[client_idx].key_info[KS_PRIMARY].key_id, vpn_client_info[client_idx].key_info[KS_LAME_DUCK].key_id, dec_key_id);
		printk("\nThere is no match key to decrypto packet!\n");	
		SMP_UNLOCK_IPSEC;
		return -1;
	}
	
	//printk("\n%s key_index=%d dec_key_id=%d\n",__FUNCTION__,key_index,dec_key_id);
	
	len=rtl_vpn_get_skb_len(skb)-out_layer_hdr_len-vpn_shared_info.digest_len;	

	if(len % CBC_BLOCK_SIZE)
	{
		SMP_UNLOCK_IPSEC;
		return -1;
	}
	
	/*
	if(len>1470)
	{
		printk("\n%s####date len=%d#####\n",__FUNCTION__, len);		
	}*/

	//SMP_LOCK_IPSEC;
	memcpy(vpn_shared_info.dec_data, data+out_layer_hdr_len+vpn_shared_info.digest_len, len);

	//printk("NIC OpenVPN DATA TO ENCRYPT:\n");
	//dump_openvpn_info(dec_data, len, 4);
	if(vpn_shared_info.auth_none==1)
	{
		scatter[0].len = len-IV_LEN;
		scatter[0].ptr = (void *) CKSEG1ADDR(vpn_shared_info.dec_data+IV_LEN); 

		err=rtl_ipsecEngine(DECRYPT_CBC_AES, _MD_NOAUTH,
    		1, scatter, vpn_shared_info.CryptResult,
    		vpn_client_info[client_idx].crypt_key_len, vpn_client_info[client_idx].key_info[key_index].dec_key,
    		0, NULL,
    		vpn_shared_info.dec_data, NULL, NULL,
   		0, len-IV_LEN);
	}
	else
	{
		scatter[0].len = len;
    		scatter[0].ptr = (void *) CKSEG1ADDR(vpn_shared_info.dec_data);

		err=rtl_ipsecEngine(DECRYPT_CBC_AES, HMAC_SHA1,
        	1, scatter, vpn_shared_info.DesCryptResult,
        	//1, scatter, NULL,
        	vpn_client_info[client_idx].crypt_key_len, vpn_client_info[client_idx].key_info[key_index].dec_key,
        	vpn_client_info[client_idx].hmac_key_len, vpn_client_info[client_idx].key_info[key_index].dec_hmac_key,
        	vpn_shared_info.dec_data, NULL, vpn_shared_info.digest,
        	IV_LEN, len-IV_LEN);		
	}
	
	//SMP_UNLOCK_IPSEC;

	if (unlikely(err))
	{
		printk("%s:%d rtl_ipsecEngine failed!!! re-init hw crypto engine!\n", __FUNCTION__,__LINE__);
		SMP_UNLOCK_IPSEC;
		
		rtl_ipsecEngine_init(DEFAULT_DESC_NUM, 2);
		//rtl_ipsecSetOption(RTL_IPSOPT_SAWB, 1);
		return -1;
	}
	else
	{		
		//printk("OpenVPN DEC RESULT:\n\n");
		//dump_openvpn_info(vpn_shared_info.dec_data+IV_LEN+PKT_ID_LEN, len-IV_LEN-PKT_ID_LEN, 1);		
		
		if(!memcmp(vpn_shared_info.dec_data+IV_LEN+PKT_ID_LEN, ping_string, PING_STRING_SIZE))
		{
			//printk("\nrecv packet is a ping packet!\n");
			//kfree_skb(skb);	
			SMP_UNLOCK_IPSEC;
			return -1;
		}
		else
		{
			//printk("OpenVPN DEC RESULT:\n\n");
			//dump_openvpn_info(vpn_shared_info.dec_data+IV_LEN, len-IV_LEN, 1);		
		}
	}

	padding_len=vpn_shared_info.dec_data[len-1];
	tmp_len=CBC_BLOCK_SIZE;	
	
	for(i=CBC_BLOCK_SIZE-padding_len; i<CBC_BLOCK_SIZE && vpn_shared_info.dec_data[len-CBC_BLOCK_SIZE+i]==padding_len; i++);

	if(i>=CBC_BLOCK_SIZE)
		tmp_len=	CBC_BLOCK_SIZE-padding_len;	

	out_data_len=len-IV_LEN-CBC_BLOCK_SIZE+tmp_len-PKT_ID_LEN;

	//skb_trim(skb, SKB_DATA_OFFSET+out_data_len);
	
	//skb->tail=skb->data+out_layer_hdr_len+out_data_len;
	//skb->len=out_layer_hdr_len+out_data_len;
	
	rtl_vpn_set_skb_tail_direct(skb, out_layer_hdr_len+out_data_len);
	
	rtl_vpn_set_skb_len(skb, out_layer_hdr_len+out_data_len);
	
	memcpy(data+out_layer_hdr_len, vpn_shared_info.dec_data+IV_LEN+PKT_ID_LEN, out_data_len);

#if 0
	*((u16*)(skb->data+out_layer_hdr_len-5))=8+out_data_len;  //udp hdr len
	*((u16*)(skb->data+out_layer_hdr_len-27))=20+8+out_data_len;  //ip hdr len

	if(out_layer_hdr_len==51)
	*((u16*)(skb->data+14+4))=2+20+8+out_data_len;
	
	
	*((u16*)(skb->data+out_layer_hdr_len-19))=0;	
	*((u16*)(skb->data+out_layer_hdr_len-19))=ip_fast_csum((u8*)(skb->data+out_layer_hdr_len-29), 5);

	*((u16*)(skb->data+out_layer_hdr_len-3))=0;	
#endif
	
	//*((u16*)(skb->data+14+20+6))=checksum((u8*)(skb->data+14+20), *((u16*)(skb->data+14+20+4))); 
	//printk("After ENC UDP checksum=%d\n", *((u16*)(skb->data+14+20+6)));
			
	//printk("HW DEC RESULT:\n");
	//dump_openvpn_info(vpn_data+vpn_shared_info.digest_len+IV_LEN, vpn_data_len-CBC_BLOCK_SIZE+tmp_len, 4);				

	//skb->protocol = htons(ETH_P_IP);
	rtl_vpn_set_skb_protocol(skb, htons(ETH_P_IP));
	//skb->dev = (struct net_device *)(vpn_shared_info.tun_dev);
	if(vpn_shared_info.tun_dev==NULL)
	{
		//skb->dev = __dev_get_by_name(&init_net, "tun0");		
		//vpn_shared_info.tun_dev=skb->dev;
		vpn_shared_info.tun_dev=rtl_vpn_get_dev_by_name("tun0");
	}
	//else
		//skb->dev=(struct net_device*)(vpn_shared_info.tun_dev);

	if(vpn_shared_info.tun_dev==NULL)
	{		
		printk("\n%s:%d vpn_shared_info.tun_dev==NULL\n", __FUNCTION__,__LINE__);		
		SMP_UNLOCK_IPSEC;
		return -1;
	}
	
	tun_dev=(struct net_device *)vpn_shared_info.tun_dev;

	//printk("\n%s tun_dev->name=%s\n",__FUNCTION__,tun_dev->name);
	
	rtl_vpn_set_skb_dev(skb, vpn_shared_info.tun_dev);

	skb_reset_mac_header(skb);
	
	//skb_pull(skb, out_layer_hdr_len);
	rtl_vpn_skb_pull(skb, out_layer_hdr_len);
	
	//dump_openvpn_info(skb->data, skb->len, 1);		

	rx_byte=rtl_vpn_get_skb_len(skb);	
	tun_dev->stats.rx_packets++;
	tun_dev->stats.rx_bytes += rx_byte;	

	//count_call_hw_engine++;

	SMP_UNLOCK_IPSEC;	

	skb_dst_drop(skb);
	
	rtl_vpn_netif_rx(skb);	
	
	return 0;				
}

int rtk_openvpn_fragment_hw_decrypto(struct sk_buff *skb)
{
	//recv data to encrypt
	//printk("NIC OpenVPN DATA TO ENCRYPT:\n");
	//dump_openvpn_info(skb->data+SKB_DATA_OFFSET, skb->data+SKB_DATA_OFFSET, 4);	
	
	u32 len, peer_ip;
	u16 peer_port;
	int err, i, padding_len, tmp_len, out_data_len, client_idx;	
	rtl_ipsecScatter_t scatter[1];

	unsigned char *data;
	//struct iphdr *iph;
	//struct udphdr *udph;
	struct net_device	*tun_dev;
	int rx_byte=0, ret_val;
	int dec_key_id=0;
	int key_index=0;	

	//printk("%s This packet is vpn data packet!\n\n",__FUNCTION__);

	skb_linearize(skb);

	//printk("\n%s skb->len=%d\n",__FUNCTION__,skb->len);
	
	data = rtl_vpn_get_skb_data(skb);
	
	//if(*((uint16*)(data+12))==htons(0x8864))
	//	iph=(struct iphdr *)(data+ETH_HDR_HLEN+PPP_HDR_LEN);
	//else
	//	iph=(struct iphdr *)(data+ETH_HDR_HLEN);	
	
	//udph=(struct udphdr *)(((unsigned char *)iph) + iph->ihl*4);	

	peer_ip = *((uint32*)(data+12));
	peer_port= *((uint16*)(data+20));
	
	//printk("\n%s peer_ip=%04x peer_port=%d\n",__FUNCTION__,peer_ip,peer_port);

	SMP_LOCK_IPSEC;
	
	for(client_idx=0;client_idx<MAX_CLIENT_NUM;client_idx++)
	if(vpn_client_info[client_idx].active_flag>0 && vpn_client_info[client_idx].peer_ip==peer_ip && vpn_client_info[client_idx].peer_port==peer_port)
		break;

	//printk("\n%s client_idx=%d\n",__FUNCTION__,client_idx);
	
	if(client_idx==MAX_CLIENT_NUM)
	{		
		SMP_UNLOCK_IPSEC;
		return -1;
	}	

	dec_key_id=data[FRAGMENT_OUT_LAYER_HDR_LEN-1] & P_KEY_ID_MASK;
	
	mod_timer(&(vpn_client_info[client_idx].ping_rec_timer), jiffies+RTL_SECONDS_TO_JIFFIES(vpn_shared_info.ping_rec_time));

	if(vpn_client_info[client_idx].key_info[KS_PRIMARY].key_id==dec_key_id)
		key_index=KS_PRIMARY;
	else if(vpn_client_info[client_idx].key_info[KS_LAME_DUCK].key_id==dec_key_id)
		key_index=KS_LAME_DUCK;
	else
	{		
		printk("\n%s key_info[KS_PRIMARY].key_id=%d  key_info[KS_LAME_DUCK].key_id=%d  dec_key_id=%d\n",__FUNCTION__,vpn_client_info[client_idx].key_info[KS_PRIMARY].key_id, vpn_client_info[client_idx].key_info[KS_LAME_DUCK].key_id, dec_key_id);
		printk("\nThere is no match key to decrypto packet!\n");		
		SMP_UNLOCK_IPSEC;
		return -1;
	}
	
	//printk("\n%s key_index=%d dec_key_id=%d\n",__FUNCTION__,key_index,dec_key_id);
	
	len=rtl_vpn_get_skb_len(skb)-FRAGMENT_OUT_LAYER_HDR_LEN-vpn_shared_info.digest_len;	

	//printk("\n%s len=%d\n",__FUNCTION__,len);

	if(len % CBC_BLOCK_SIZE)
	{
		printk("\n%s len is not times of CBC_BLOCK_SIZE!!! len=%d\n",__FUNCTION__,len);
		SMP_UNLOCK_IPSEC;
		return -1;
	}	

	//SMP_LOCK_IPSEC;
	memcpy(vpn_shared_info.dec_data, data+FRAGMENT_OUT_LAYER_HDR_LEN+vpn_shared_info.digest_len, len);

	//printk("NIC OpenVPN DATA TO ENCRYPT:\n");
	//dump_openvpn_info(dec_data, len, 4);
	if(vpn_shared_info.auth_none==1)
	{
		scatter[0].len = len-IV_LEN;
		scatter[0].ptr = (void *) CKSEG1ADDR(vpn_shared_info.dec_data+IV_LEN); 	

		err=rtl_ipsecEngine(DECRYPT_CBC_AES, _MD_NOAUTH,
		1, scatter, vpn_shared_info.CryptResult,
		vpn_client_info[client_idx].crypt_key_len, vpn_client_info[client_idx].key_info[key_index].dec_key,
		0, NULL,
		vpn_shared_info.dec_data, NULL, NULL,
	   	0, len-IV_LEN);
	}
	else
	{
		scatter[0].len = len;
    		scatter[0].ptr = (void *) CKSEG1ADDR(vpn_shared_info.dec_data);

		err=rtl_ipsecEngine(DECRYPT_CBC_AES, HMAC_SHA1,
        	1, scatter, vpn_shared_info.DesCryptResult,
        	//1, scatter, NULL,
        	vpn_client_info[client_idx].crypt_key_len, vpn_client_info[client_idx].key_info[key_index].dec_key,
        	vpn_client_info[client_idx].hmac_key_len, vpn_client_info[client_idx].key_info[key_index].dec_hmac_key,
        	vpn_shared_info.dec_data, NULL, vpn_shared_info.digest,
        	IV_LEN, len-IV_LEN);
	}
	
	//SMP_UNLOCK_IPSEC;

	if (unlikely(err))
	{
		printk("%s:%d rtl_ipsecEngine failed\n", __FUNCTION__,__LINE__);
		SMP_UNLOCK_IPSEC;
		
		rtl_ipsecEngine_init(DEFAULT_DESC_NUM, 2);
		//rtl_ipsecSetOption(RTL_IPSOPT_SAWB, 1);
		return -1;
	}
	else
	{		
		//printk("OpenVPN DEC RESULT:\n\n");
		//dump_openvpn_info(vpn_shared_info.dec_data+IV_LEN, len-IV_LEN, 1);		
		/*
		if(!memcmp(vpn_shared_info.dec_data+IV_LEN+PKT_ID_LEN, ping_string, PING_STRING_SIZE))
		{
			//printk("\nrecv packet is a ping packet!\n");
			kfree_skb(skb);			
			return 0;
		}*/
	}

	padding_len=vpn_shared_info.dec_data[len-1];
	tmp_len=CBC_BLOCK_SIZE;	
	
	for(i=CBC_BLOCK_SIZE-padding_len; i<CBC_BLOCK_SIZE && vpn_shared_info.dec_data[len-CBC_BLOCK_SIZE+i]==padding_len; i++);

	if(i>=CBC_BLOCK_SIZE)
		tmp_len=	CBC_BLOCK_SIZE-padding_len;	

	out_data_len=len-IV_LEN-CBC_BLOCK_SIZE+tmp_len-PKT_ID_LEN;

	//skb_trim(skb, SKB_DATA_OFFSET+out_data_len);
	
	//skb->tail=skb->data+out_layer_hdr_len+out_data_len;
	//skb->len=out_layer_hdr_len+out_data_len;
	
	rtl_vpn_set_skb_tail_direct(skb, FRAGMENT_OUT_LAYER_HDR_LEN+out_data_len);
	
	rtl_vpn_set_skb_len(skb, FRAGMENT_OUT_LAYER_HDR_LEN+out_data_len);
	
	memcpy(data+FRAGMENT_OUT_LAYER_HDR_LEN, vpn_shared_info.dec_data+IV_LEN+PKT_ID_LEN, out_data_len);

#if 0
	*((u16*)(skb->data+out_layer_hdr_len-5))=8+out_data_len;  //udp hdr len
	*((u16*)(skb->data+out_layer_hdr_len-27))=20+8+out_data_len;  //ip hdr len

	if(out_layer_hdr_len==51)
	*((u16*)(skb->data+14+4))=2+20+8+out_data_len;
	
	
	*((u16*)(skb->data+out_layer_hdr_len-19))=0;	
	*((u16*)(skb->data+out_layer_hdr_len-19))=ip_fast_csum((u8*)(skb->data+out_layer_hdr_len-29), 5);

	*((u16*)(skb->data+out_layer_hdr_len-3))=0;	
#endif
	
	//*((u16*)(skb->data+14+20+6))=checksum((u8*)(skb->data+14+20), *((u16*)(skb->data+14+20+4))); 
	//printk("After ENC UDP checksum=%d\n", *((u16*)(skb->data+14+20+6)));
			
	//printk("HW DEC RESULT:\n");
	//dump_openvpn_info(vpn_data+vpn_shared_info.digest_len+IV_LEN, vpn_data_len-CBC_BLOCK_SIZE+tmp_len, 4);				

	//skb->protocol = htons(ETH_P_IP);
	rtl_vpn_set_skb_protocol(skb, htons(ETH_P_IP));
	//skb->dev = (struct net_device *)(vpn_shared_info.tun_dev);
	if(vpn_shared_info.tun_dev==NULL)
	{
		//skb->dev = __dev_get_by_name(&init_net, "tun0");		
		//vpn_shared_info.tun_dev=skb->dev;
		vpn_shared_info.tun_dev=rtl_vpn_get_dev_by_name("tun0");
	}
	//else
		//skb->dev=(struct net_device*)(vpn_shared_info.tun_dev);

	tun_dev=(struct net_device *)vpn_shared_info.tun_dev;	

	//skb_reset_network_header(skb);
	//skb_pull(skb, out_layer_hdr_len);
	rtl_vpn_skb_pull(skb, FRAGMENT_OUT_LAYER_HDR_LEN);

	skb_reset_network_header(skb);
	
	rx_byte=rtl_vpn_get_skb_len(skb);
	tun_dev->stats.rx_packets++;
	tun_dev->stats.rx_bytes += rx_byte;
	//printk("\n%s:%d###rx_byte=%d\n",__FUNCTION__,__LINE__,rx_byte);

	rtl_vpn_set_skb_dev(skb, vpn_shared_info.tun_dev);		
	
	//printk("\n%s:%d skb->dev->name=%s skb->len=%d\n",__FUNCTION__,__LINE__,skb->dev->name,skb->len);            
	//printk("HW DEC RESULT:\n");
	//dump_openvpn_info(skb->data, 20, 1);

	skb_dst_drop(skb);

	SMP_UNLOCK_IPSEC;

	rtl_vpn_netif_rx(skb);	
	
	return 0;				
}
EXPORT_SYMBOL(rtk_openvpn_fragment_hw_decrypto);



int openvpn_fast_to_wan(struct sk_buff *skb)
{
	u32 header_len, padding_len, peer_virtual_ip;
	//u16 peer_port;
	int i, orig_len, client_idx;
	unsigned char *data;
	//struct iphdr *iph;
	//struct udphdr *udph;
	//struct tun_struct *tun;
	struct net_device	*tun_dev;	
	
	if(vpn_shared_info.wan_dev==NULL)
		return 0;	

	data = rtl_vpn_get_skb_data(skb);	

	//if(*((u16 *)(data+6)) & 0x3fff)
	//	goto no_handle_fragment_pkt;
	

	//printk("recv data from tun0:\n");
	//dump_openvpn_info(skb->data, skb->len, 4);
	
	if(vpn_shared_info.tun_dev==NULL)
		vpn_shared_info.tun_dev=rtl_vpn_get_skb_dev(skb);

	tun_dev=(struct net_device *)vpn_shared_info.tun_dev;

	//tun = netdev_priv(vpn_shared_info.tun_dev);
	
	//printk("%s TUN NAME %s\n\n",__FUNCTION__,((struct net_device *)(vpn_shared_info.tun_dev))->name);

	
	//iph=(struct iphdr *)data;
	//udph=(struct udphdr *)(((unsigned char *)iph) + iph->ihl*4);
	
	peer_virtual_ip=*((uint32*)(data+16));
	//peer_virtual_ip=iph->daddr;
	
	//printk("\n%s peer_virtual_ip=%04x\n",__FUNCTION__,peer_virtual_ip);
	
	for(client_idx=0;client_idx<MAX_CLIENT_NUM;client_idx++)
	if(vpn_client_info[client_idx].active_flag>0 && vpn_client_info[client_idx].virtual_ip==peer_virtual_ip)
		break;

	//printk("\n%s client_idx=%d\n",__FUNCTION__,client_idx);

	if(client_idx==MAX_CLIENT_NUM)
	{
		//printk("%s client_idx=%d\n\n",__FUNCTION__,client_idx);
		return 0;	
	}

	if(memcmp(vpn_client_info[client_idx].peer_layer_hdr, EMPTY_MAC_ADDR, 6)==0)
		return 0;
	else
	{
		//printk("%s CLIENT %d layer header len %d:\n", __FUNCTION__, client_idx, vpn_shared_info.local_layer_hdr_len);
		//dump_openvpn_info(vpn_client_info[client_idx].peer_layer_hdr, vpn_shared_info.local_layer_hdr_len, 4);
	}

	//printk("%s client_idx=%d\n\n",__FUNCTION__,client_idx);

	//padding
	orig_len=rtl_vpn_get_skb_len(skb);
	padding_len=CBC_BLOCK_SIZE-(orig_len+PKT_ID_LEN)%CBC_BLOCK_SIZE;	
	//skb_put(skb, padding_len);	
	rtl_vpn_skb_put(skb, padding_len);
	
	 for(i=0; i<padding_len; i++)
		data[orig_len+i]=padding_len;	 
	
	header_len = vpn_shared_info.local_layer_hdr_len+vpn_shared_info.digest_len+IV_LEN+PKT_ID_LEN;
	if (rtl_vpn_skb_headroom(skb) < header_len || rtl_vpn_skb_cloned(skb) || rtl_vpn_skb_shared(skb))
	{
		void *new_skb = (void*)skb_realloc_headroom(skb, header_len);
		if (!new_skb) 
		{
			printk("%s: skb_realloc_headroom failed!\n", __FUNCTION__);
			return 0;
		}
		dev_kfree_skb(skb);
		skb = new_skb;
	}

	rtl_vpn_skb_push(skb, header_len);	

	data = rtl_vpn_get_skb_data(skb);
	
	memcpy(data, vpn_client_info[client_idx].peer_layer_hdr, vpn_shared_info.local_layer_hdr_len);

	//*((u32 *)(data+header_len-PKT_ID_LEN))=0;	
	
	*((u8 *)(data+header_len-1))=0xfa;	
	//*((u8 *)(data+vpn_shared_info.local_layer_hdr_len-1))=0x30;
	*((u8 *)(data+vpn_shared_info.local_layer_hdr_len-1))=0;

	*((u16*)(data+vpn_shared_info.local_layer_hdr_len-5))=rtl_vpn_get_skb_len(skb)-vpn_shared_info.local_layer_hdr_len+9;
	//udph->len=rtl_vpn_get_skb_len(skb)-vpn_shared_info.local_layer_hdr_len+1+UDP_HDR_LEN;
	*((u16*)(data+vpn_shared_info.local_layer_hdr_len-27))=rtl_vpn_get_skb_len(skb)-vpn_shared_info.local_layer_hdr_len+29;
	//iph->tot_len=rtl_vpn_get_skb_len(skb)-vpn_shared_info.local_layer_hdr_len+1+UDP_HDR_LEN+iph->ihl*4;

	if(vpn_shared_info.local_layer_hdr_len==MAX_OUT_LAYER_HDR_LEN)
		*((u16*)(data+ETH_HDR_HLEN+4))=rtl_vpn_get_skb_len(skb)-20;

	//skb_reset_mac_header(skb); 				//set mac header
	//skb_set_network_header(skb,vpn_shared_info.local_layer_hdr_len-29);			//set ip header
	//skb_set_transport_header(skb,vpn_shared_info.local_layer_hdr_len-9);
	
	//skb->dev=vpn_shared_info.wan_dev;

	//vpn_shared_info.wan_dev=rtl_vpn_get_dev_by_name("eth1");
	//if(vpn_shared_info.local_layer_hdr_len==MAX_OUT_LAYER_HDR_LEN)
	//	vpn_shared_info.wan_dev=rtl_vpn_get_dev_by_name("eth1");

	tun_dev->stats.tx_packets++;
	tun_dev->stats.tx_bytes += orig_len;
	
	rtl_vpn_set_skb_dev(skb, vpn_shared_info.wan_dev);

	 	//set transport header

	//dump_openvpn_info(skb->data, skb->len, 1);
		
	//printk("skb->dev->name=%s\n", skb->dev->name);

	//printk("%s udp_srcport=%d\n",__FUNCTION__,*((uint16*)(data+34)));
	
	//skb->dev->netdev_ops->ndo_start_xmit(skb, skb->dev);

//no_handle_fragment_pkt:
	rtl_vpn_call_skb_ndo_start_xmit(skb);	
	
	return 1;	
}
EXPORT_SYMBOL(openvpn_fast_to_wan);


int rtl_fast_openvpn_init(void)
{
	int i;
	//create kernel netlink socket
	struct netlink_kernel_cfg cfg = {
		.input	= rtk_openvpn_netlink_receive,
	};

	printk("\n%s call netlink_kernel_create()!!!\n",__FUNCTION__);
	
  	nl_openvpn_sk = netlink_kernel_create(&init_net, OPENVPN_NETLINK_CRYPTO, &cfg);

  	if (!nl_openvpn_sk) 
	{
    		printk(KERN_ERR "kernel create openvpn netlink socket fail!\n");
		return -1;
  	}

	for(i=0;i<MAX_CLIENT_NUM;i++)
	{
		memset(&(vpn_client_info[i].key_info[KS_PRIMARY]), 0, sizeof(OpenVPN_Key_Info));
		memset(&(vpn_client_info[i].key_info[KS_LAME_DUCK]), 0, sizeof(OpenVPN_Key_Info));
	}	
	
	memset(vpn_client_info, 0, MAX_CLIENT_NUM*sizeof(OpenVPN_Info));

	memset(&vpn_shared_info, 0, sizeof(Shared_OpenVPN_Info));
	vpn_shared_info.digest_len=DIGEST_LEN;
	
	vpn_shared_info.enc_data=(u8 *) UNCACHED_MALLOC(MAX_OPENVPN_PAYLOAD_LEN);
	vpn_shared_info.dec_data=(u8 *) UNCACHED_MALLOC(MAX_OPENVPN_PAYLOAD_LEN);
	vpn_shared_info.CryptResult=(u8 *) UNCACHED_MALLOC(MAX_OPENVPN_PAYLOAD_LEN);
	vpn_shared_info.DesCryptResult=(u8 *) UNCACHED_MALLOC(MAX_OPENVPN_PAYLOAD_LEN);
	vpn_shared_info.digest=(u8 *) UNCACHED_MALLOC(MAX_DIGEST_LEN);
	
	vpn_shared_info.local_port=DEFAULT_PORT_NUM;
	vpn_shared_info.local_port=ntohs(vpn_shared_info.local_port);
	vpn_shared_info.ip_id=1;
	
	return 0;
}










































