/*
 *  802.11k beacon processing routines
 *
 *  Copyright (c) 2017 Realtek Semiconductor Corp.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 */

#define _8192CD_11K_BEACON_C_

#ifdef __KERNEL__
#include <linux/module.h>
#include <asm/byteorder.h>
#elif defined(__ECOS)
#include <cyg/io/eth/rltk/819x/wrapper/sys_support.h>
#include <cyg/io/eth/rltk/819x/wrapper/skbuff.h>
#include <cyg/io/eth/rltk/819x/wrapper/timer.h>
#include <cyg/io/eth/rltk/819x/wrapper/wrapper.h>
#endif

#include "../8192cd_cfg.h"

#if !defined(__KERNEL__) && !defined(__ECOS)
#include "../sys-support.h"
#endif

#include "../8192cd.h"
#ifdef __KERNEL__
#include "../ieee802_mib.h"
#elif defined(__ECOS)
#include <cyg/io/eth/rltk/819x/wlan/ieee802_mib.h>
#endif
#include "../8192cd_util.h"
#include "../8192cd_headers.h"
#include "../8192cd_debug.h"

#ifdef DOT11K
typedef struct _OP_CLASS_
{
    unsigned char     op_class;
    unsigned char     band; /* 0: 5g, 1: 2g*/
    const unsigned char* channel_array;
} OP_CLASS;



const static unsigned char null_mac[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
const static unsigned char wildcard_bssid[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

const static unsigned char beacon_channel_81[] = {13/*channel num*/,  1, 2, 3 ,4 ,5, 6, 7, 8, 9, 10, 11, 12, 13};
const static unsigned char beacon_channel_115[] = {4/*channel num*/, 36, 40, 44, 48};
const static unsigned char beacon_channel_118[] = {4/*channel num*/, 52, 56, 60, 64};
const static unsigned char beacon_channel_121[] = {11/*channel num*/, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140};
const static unsigned char beacon_channel_124[] = {4/*channel num*/, 149, 153, 157, 161};
const static unsigned char beacon_channel_125[] = {6/*channel num*/, 149, 153, 157, 161, 165, 169};


/*Global Operating Classes*/
const static OP_CLASS global_op_class[] =
{
    {81,  1,  beacon_channel_81},
    {115, 0,  beacon_channel_115},
    {118, 0,  beacon_channel_118},    
    {121, 0,  beacon_channel_121},
    {124, 0,  beacon_channel_124},
    {125, 0,  beacon_channel_125},
};

/*Operating Classes in United States*/
const static OP_CLASS us_op_class[] =
{
    {1,   0,  beacon_channel_115},
    {2,   0,  beacon_channel_118},
    {3,   0,  beacon_channel_124},
    {4,   0,  beacon_channel_121},
    {5,   0,  beacon_channel_125},
    {12,  1,  beacon_channel_81},
};

/*Operating Classes in Europe*/
const static OP_CLASS eu_op_class[] =
{
    {1,   0,  beacon_channel_115},
    {2,   0,  beacon_channel_118},
    {3,   0,  beacon_channel_121},    
    {4,   1,  beacon_channel_81},
    {17,  0,  beacon_channel_125},
};

/*Operating Classes in Japan*/
const static OP_CLASS jp_op_class[] =
{
    {1,   0,  beacon_channel_115},
    {30,  1,  beacon_channel_81},
    {32,   0,  beacon_channel_118},
    {33,   0,  beacon_channel_118},
    {34,   0,  beacon_channel_121},
    {35,   0,  beacon_channel_121},
};

static const OP_CLASS* check_op_class(struct rtl8192cd_priv *priv, unsigned char op_class)
{
    int i = 0;
    const OP_CLASS * op_class_array = NULL;
    int op_class_array_len;

    switch(priv->pmib->dot11StationConfigEntry.dot11RegDomain)
    {
        case DOMAIN_FCC: /* FCC */
            op_class_array = us_op_class;
            op_class_array_len = sizeof(us_op_class)/ sizeof(OP_CLASS);
            break;
        case DOMAIN_ETSI: /* ETSI */
            op_class_array = eu_op_class;
            op_class_array_len = sizeof(eu_op_class)/ sizeof(OP_CLASS);
            break;
        case DOMAIN_MKK: /* JP */
            op_class_array = jp_op_class;
            op_class_array_len = sizeof(jp_op_class)/ sizeof(OP_CLASS);
            break;
        default:
            op_class_array = NULL;
            op_class_array_len = 0;
            break;
    }

    if(op_class_array)
    {
        for(i = 0; i < op_class_array_len; i++)
        {
            if(op_class == op_class_array[i].op_class)
            {
                break;
            }
        }

        if(i < op_class_array_len)
        {
#ifndef RTK_MULTI_AP 
            if((op_class_array[i].band == 1 && priv->pmib->dot11RFEntry.phyBandSelect & PHY_BAND_2G) ||
                    (op_class_array[i].band == 0 && priv->pmib->dot11RFEntry.phyBandSelect & PHY_BAND_5G))
#endif
            {
                return &op_class_array[i];
            }
        }
    }



    /* check global operating class*/
    op_class_array = global_op_class;
    op_class_array_len = sizeof(global_op_class)/ sizeof(OP_CLASS);
    for(i = 0; i < op_class_array_len; i++)
    {
        if(op_class == op_class_array[i].op_class)
        {
            break;
        }
    }

    if(i < op_class_array_len)
    {
#ifndef RTK_MULTI_AP
        if((op_class_array[i].band == 1 && priv->pmib->dot11RFEntry.phyBandSelect & PHY_BAND_2G) ||
                (op_class_array[i].band == 0 && priv->pmib->dot11RFEntry.phyBandSelect & PHY_BAND_5G))
#endif
        {
            return &op_class_array[i];
        }
    }

    return NULL;

}


static int check_ap_channel_report(struct rtl8192cd_priv *priv, struct dot11k_ap_channel_report* ap_channel_report)
{
    int i,j;
    const OP_CLASS * op_class = check_op_class(priv, ap_channel_report->op_class);
    if(op_class)
    {
        for(i = 0; i < ap_channel_report->len-1; i++)
        {
            for(j = 1; j <= op_class->channel_array[0]; j++)
            {
                if(ap_channel_report->channel[i]== op_class->channel_array[j])
                    break;
            }

            if(j > op_class->channel_array[0])
                return 1; /* channel is not in operating class*/
        }
    }
    else
    {
        return 1; /* the operating class is not supported*/
    }

    return 0;

}


static void get_channel_of_ap_report(struct rtl8192cd_priv *priv, struct dot11k_ap_channel_report *ap_report)
{
    int i,j;
    const OP_CLASS * op_class;
    if(ap_report->len == 0)
        return;
    op_class =  check_op_class(priv, ap_report->op_class);
    if(op_class == NULL)
        return;

    for(i = 0; i < ap_report->len-1; i++)
    {

        for(j = 1; j <= op_class->channel_array[0]; j++)
        {
            if(op_class->channel_array[j] == ap_report->channel[i])
                break;
        }
        if(j > op_class->channel_array[0])
            continue; /* channel is not in operating class*/


        for(j = 0; j < priv->available_chnl_num; j++)
        {
            if(priv->available_chnl[j] == ap_report->channel[i])
                break;
        }

        if(j >= priv->available_chnl_num)
            continue; /* channel is not in available_chnl*/

        for(j = 0; j < priv->rm.beacon_channel_num; j++)
        {
            if(priv->rm.beacon_channel[j] == ap_report->channel[i])
            {
                break;
            }
        }

        if(j >= priv->rm.beacon_channel_num && priv->rm.beacon_channel_num < MAX_BEACON_REQ_CHANNEL)
        {
            priv->rm.beacon_channel[priv->rm.beacon_channel_num] = ap_report->channel[i];
            priv->rm.beacon_channel_num++;
        }
    }
}

static unsigned char get_op_class_from_apreport(struct rtl8192cd_priv *priv, unsigned char channel)
{
    int i,j;
    for(i = 0; i < MAX_AP_CHANNEL_REPORT; i++)
    {
        if(priv->rm.beacon_req.ap_channel_report[i].len == 0)
            continue;
        for(j = 0; j < MAX_AP_CHANNEL_NUM; j++)
        {
            if(priv->rm.beacon_req.ap_channel_report[i].channel[j] == channel)
                return priv->rm.beacon_req.ap_channel_report[i].op_class;

        }
    }
    for(i = 0; i < MAX_AP_CHANNEL_REPORT; i++)
    {
        if(priv->rm_ap_channel_report[i].len == 0)
            continue;
        for(j = 0; j < MAX_AP_CHANNEL_NUM; j++)
        {
            if(priv->rm_ap_channel_report[i].channel[j] == channel)
                return priv->rm_ap_channel_report[i].op_class;

        }
    }
    return 0;

}


unsigned char rm_get_op_class(struct rtl8192cd_priv *priv, unsigned char channel)
{
    int i,j;
    const OP_CLASS * op_class_array = NULL;
    int op_class_array_len;
    unsigned char * channel_array;

    switch(priv->pmib->dot11StationConfigEntry.dot11RegDomain)
    {
        case DOMAIN_FCC: /* FCC */
            op_class_array = us_op_class;
            op_class_array_len = sizeof(us_op_class)/ sizeof(OP_CLASS);
            break;
        case DOMAIN_ETSI: /* ETSI */
            op_class_array = eu_op_class;
            op_class_array_len = sizeof(eu_op_class)/ sizeof(OP_CLASS);
            break;
        case DOMAIN_MKK: /* JP */
            op_class_array = jp_op_class;
            op_class_array_len = sizeof(jp_op_class)/ sizeof(OP_CLASS);
            break;
        default:
            op_class_array = global_op_class;
            op_class_array_len = sizeof(global_op_class)/ sizeof(OP_CLASS);;
            break;
    }
    

    for(i = 0; i < op_class_array_len; i++)
    {
        channel_array = op_class_array[i].channel_array;
        for(j = 0; j < channel_array[0]; j++) {
            if(channel == channel_array[j+1])
                return op_class_array[i].op_class;
        }        
    }


    return 0;
}


static unsigned char * construct_beacon_request_ie(struct rtl8192cd_priv *priv, unsigned char	*pbuf, unsigned int *frlen,
        unsigned char token, struct dot11k_beacon_measurement_req * beacon_req)
{
    int i;
    unsigned char temp[100];
    unsigned int len;
    unsigned int ssid_len;

    temp[0] = token;
    temp[1] = 0; /*measurement request mode*/
    temp[2] = MEASUREMENT_TYPE_BEACON; /*measurement type*/

    temp[3] = beacon_req->op_class; //Operating class
    temp[4] = beacon_req->channel; // channel number
    *(unsigned short *)(temp + 5) = cpu_to_le16(beacon_req->random_interval);/*randomization interval*/
    *(unsigned short *)(temp + 7) = cpu_to_le16(beacon_req->measure_duration); /*measurement duration*/
    temp[9] = beacon_req->mode;

    if(memcmp(beacon_req->bssid, null_mac, MACADDRLEN) == 0)
    {
        memset(temp + 10, 0xFF, MACADDRLEN); /*wildcard bssid*/
    }
    else
    {
        memcpy(temp + 10, beacon_req->bssid, MACADDRLEN);
    }
    len = 16;

    /*construct ssid subelement*/
    if(beacon_req->ssid[0] != 0)
    {
        ssid_len = strlen(beacon_req->ssid);
        temp[len] = _SSID_IE_;
        temp[len + 1] = ssid_len;
        memcpy(temp + len + 2, (unsigned char *)beacon_req->ssid, ssid_len);
        len += ssid_len + 2;
    }
    /*construct report detailed*/
    if(beacon_req->report_detail == 0 || beacon_req->report_detail == 1 || beacon_req->report_detail == 2)
    {
        temp[len] = _REPORT_DETAIL_SUBIE_;
        temp[len + 1] = 1;
        temp[len + 2] = beacon_req->report_detail;
        len += 3;

        /*construct request ie*/
        if(beacon_req->report_detail == 1)
        {
            if(beacon_req->request_ie_len)
            {
                temp[len] = _REQUEST_IE_;
                temp[len + 1] = beacon_req->request_ie_len;
                memcpy(temp + len + 2, beacon_req->request_ie, beacon_req->request_ie_len);
                len += beacon_req->request_ie_len + 2;
            }
        }
    }

    /*construct AP channel report*/
    if(beacon_req->channel == 255)
    {
        for(i = 0; i < MAX_AP_CHANNEL_REPORT; i++)
        {
            if(beacon_req->ap_channel_report[i].len)
            {
                temp[len] = _AP_CHANNEL_REPORT_IE_;
                temp[len + 1] = beacon_req->ap_channel_report[i].len;
                memcpy(temp + len + 2, &beacon_req->ap_channel_report[i].op_class, beacon_req->ap_channel_report[i].len);
                len += beacon_req->ap_channel_report[i].len + 2;
            }
        }
    }

    pbuf = set_ie(pbuf, _MEASUREMENT_REQUEST_IE_, len, temp, frlen);
    return pbuf;
}

static int issue_beacon_measurement_request(struct rtl8192cd_priv *priv, struct stat_info *pstat,
        struct dot11k_beacon_measurement_req* beacon_req)
{
    unsigned char   *pbuf;
    unsigned int frlen;
    int ret;

    DECLARE_TXINSN(txinsn);

    txinsn.q_num = MANAGE_QUE_NUM;
    txinsn.fr_type = _PRE_ALLOCMEM_;
    txinsn.tx_rate = find_rate(priv, NULL, 0, 1);
#ifndef TX_LOWESTRATE
    txinsn.lowest_tx_rate = txinsn.tx_rate;    
#endif
    txinsn.fixed_rate = 1;
#ifdef CONFIG_IEEE80211W		
	if(pstat)
		txinsn.isPMF = pstat->isPMF;
	else
		txinsn.isPMF = 0;	
#endif		

    pbuf = txinsn.pframe = get_mgtbuf_from_poll(priv);
    if (pbuf == NULL)
        goto issue_beacon_request_fail;

    txinsn.phdr = get_wlanhdr_from_poll(priv);
    if (txinsn.phdr == NULL)
        goto issue_beacon_request_fail;

    memset((void *)(txinsn.phdr), 0, sizeof(struct wlan_hdr));

    pbuf[0] = _RADIO_MEASUREMENT_CATEGORY_ID_;
    pbuf[1] = _RADIO_MEASUREMENT_REQEST_ACTION_ID_;

    if (!(++pstat->dialog_token))	// dialog token set to a non-zero value
        pstat->dialog_token++;

    pstat->rm.dialog_token = pstat->dialog_token;
    pbuf[2] = pstat->dialog_token;
    pbuf[3] = pbuf[4] = 0; /*repetition*/
    frlen = 5;

    pbuf = construct_beacon_request_ie(priv, pbuf + frlen, &frlen, 1, beacon_req);
    txinsn.fr_len = frlen;

    SetFrameSubType((txinsn.phdr), WIFI_WMM_ACTION);
#ifdef CONFIG_IEEE80211W
	if (txinsn.isPMF)
		*(unsigned char*)(txinsn.phdr+1) |= BIT(6); // enable privacy 
#endif	
    memcpy((void *)GetAddr1Ptr((txinsn.phdr)), pstat->cmn_info.mac_addr, MACADDRLEN);
    memcpy((void *)GetAddr2Ptr((txinsn.phdr)), GET_MY_HWADDR, MACADDRLEN);
    memcpy((void *)GetAddr3Ptr((txinsn.phdr)), BSSID, MACADDRLEN);

#if defined(WIFI_WMM)
    ret = check_dz_mgmt(priv, pstat, &txinsn);
    
    if (ret < 0)
        goto issue_beacon_request_fail;
    else if (ret == 1)
        return 0;
    else
#endif
    if ((rtl8192cd_firetx(priv, &txinsn)) == SUCCESS)
        return 0;

issue_beacon_request_fail:

    if (txinsn.phdr)
        release_wlanhdr_to_poll(priv, txinsn.phdr);
    if (txinsn.pframe)
        release_mgtbuf_to_poll(priv, txinsn.pframe);
    return -1;
}

int is_req_bssid(struct stat_info *pstat, unsigned char* bssid)
{
	if(memcmp(pstat->rm.beacon_req.bssid, bssid,MACADDRLEN) == 0)
		return 1;
	return 0;
}

int rm_fill_beacon_report_to_neighbor_report(struct rtl8192cd_priv *priv, struct stat_info *pstat, struct dot11k_beacon_measurement_report* beacon_rep)
{
    int i, len, empty_slot;
    unsigned char *pSSID, *bssid, *p2;
    unsigned char cap_info;
    unsigned int oldest_aging;
    int oldest_idx;
    unsigned char *ssid_ptr = NULL;
    int ssid_len = 0;

    bssid = beacon_rep->info.bssid;

    if (beacon_rep->subelements_len >= 14) {
        pSSID = get_ie(beacon_rep->subelements + 14, _SSID_IE_, &len, beacon_rep->subelements_len);
        if ((pSSID != NULL) &&      // NULL AP case 1
            (len > 0) &&            // NULL AP case 2
            (*(pSSID+2) != '\0'))   // NULL AP case 3 (like 8181/8186)
        {
            ssid_ptr = pSSID+2;
            ssid_len = len;
        }
    }
    
    /*search for neighbor report*/
    for(i = 0, empty_slot = -1; i < MAX_NEIGHBOR_REPORT; i++)
    {
        if((priv->rm_neighbor_bitmask[i>>3] & (1<<(i&7))) == 0)
        {
            if(empty_slot == -1)
                empty_slot = i;
        }
        else if(0 == memcmp(bssid, priv->rm_neighbor_report[i].bssid, MACADDRLEN)) /*same BSSID*/
        {
            break;
        }
    }
    if(i == MAX_NEIGHBOR_REPORT && empty_slot != -1)   /*not found, and has empty slot*/
    {
        i = empty_slot;        
        memcpy(priv->rm_neighbor_report[i].bssid, bssid, MACADDRLEN);
    }
    
    if(i == MAX_NEIGHBOR_REPORT)  /*not found and no empty slot, find the oldest neighbor and replace it*/
    {
        for(i = 0; i < MAX_NEIGHBOR_REPORT; i++)
        {
            if(priv->rm_neighbor_bitmask[i>>3] & (1<<(i&7)))
            {
                /* select oldest entry except bssid requested by beacon request*/
                if(oldest_aging < priv->rm_neighbor_info[i].aging && 
                   is_req_bssid(pstat, priv->rm_neighbor_report[i].bssid) == 0) {
                    oldest_aging = priv->rm_neighbor_info[i].aging;
                    oldest_idx = i;
                }
            }
        }
        i = oldest_idx;        
        memcpy(priv->rm_neighbor_report[i].bssid, bssid, MACADDRLEN);
    }
    DEBUG_INFO("Fill bcn_report into neighbor report: %02X%02X%02X%02X%02X%02X, SSID_len = %d\n", priv->rm_neighbor_report[i].bssid[0],priv->rm_neighbor_report[i].bssid[1],
																			   priv->rm_neighbor_report[i].bssid[2],priv->rm_neighbor_report[i].bssid[3],
																			   priv->rm_neighbor_report[i].bssid[4],priv->rm_neighbor_report[i].bssid[5],
																			   ssid_len);
    priv->rm_neighbor_report[i].bssinfo.value = 0x000E;
    if (check_op_class(priv, beacon_rep->info.op_class) != NULL && priv->rm_neighbor_report[i].op_class != beacon_rep->info.op_class)
        priv->rm_neighbor_report[i].op_class = beacon_rep->info.op_class;
    // IoT: The channel number in the beacon report of Netgear R7000/Iphone 6 is the central channel.
    //if (rm_get_op_class(priv, beacon_rep->info.channel) != 0 && priv->rm_neighbor_report[i].channel != beacon_rep->info.channel)
    priv->rm_neighbor_report[i].channel = beacon_rep->info.channel;
    priv->rm_neighbor_report[i].phytype = 0;

    if (beacon_rep->subelements_len >= 14) {
        memset(&priv->rm_neighbor_report[i].bssinfo.field,0,4);
        cap_info = *(beacon_rep->subelements + 13);
        if(cap_info & 0x01) { /*Specture mgmt*/
            priv->rm_neighbor_report[i].bssinfo.field.cap_spectrum = 1;
        }
        if(cap_info & 0x02) { /*Qos*/
            priv->rm_neighbor_report[i].bssinfo.field.cap_qos = 1;
        }
        if(cap_info & 0x08) { /*APSD*/
            priv->rm_neighbor_report[i].bssinfo.field.cap_apsd = 1;
        }
        if(cap_info & 0x10) { /*Radio Measurement*/
            priv->rm_neighbor_report[i].bssinfo.field.cap_rm = 1;
        }            
        if(cap_info & 0x40) { /*Delayed Block Ack*/
            priv->rm_neighbor_report[i].bssinfo.field.cap_delay_ba = 1;
        }  
        if(cap_info & 0x80) { /*Immediate  Block Ack*/
            priv->rm_neighbor_report[i].bssinfo.field.cap_im_ba = 1;
        } 
        
        /* checking HT_CAP IE */
        p2 = get_ie(beacon_rep->subelements + 14, _HT_CAP_, &len, beacon_rep->subelements_len);
        if (p2)
        {
            if (priv->ht_cap_len == len) {
                if(memcmp(p2+2, (unsigned char *)&priv->ht_cap_buf, priv->ht_cap_len) == 0) /*get HT CAP ie, check the content is same as our AP*/
                    priv->rm_neighbor_report[i].bssinfo.field.high_tp = 1;
            }   
        }
        
        /* checking BSS Load IE */
        p2 = get_ie(beacon_rep->subelements + 14, _BSS_LOAD_IE_, &len, beacon_rep->subelements_len);
        if (p2)
        {
            priv->rm_neighbor_info[i].bssload.sta_count = le16_to_cpu(*(unsigned short *)(p2+2));
            priv->rm_neighbor_info[i].bssload.channel_utilization = *(p2+4);
        }  
    }
    
    if (ssid_ptr != NULL && ssid_len > 0) {
        memcpy(priv->rm_neighbor_info[i].ssid, ssid_ptr, ssid_len);
        priv->rm_neighbor_info[i].ssid[ssid_len] = 0;
    }
    priv->rm_neighbor_info[i].aging = 0;
    priv->rm_neighbor_info[i].source = 1;
    priv->rm_neighbor_bitmask[i>>3] |= (1<<(i&7));        

#ifdef CONFIG_IEEE80211V
    if(WNM_ENABLE) {
        priv->rm_neighbor_report[i].subelemnt.subelement_id = _WNM_BSS_TRANS_CANDIDATE_PREFRENCE_;
        priv->rm_neighbor_report[i].subelemnt.len = 1;
        priv->rm_neighbor_report[i].subelemnt.preference =
            getPreferredVal(priv, priv->rm_neighbor_info[i].bssload.channel_utilization, 0, 0);
    }
#endif
}

int rm_parse_beacon_report(struct rtl8192cd_priv *priv, struct stat_info *pstat,
                           unsigned char *pframe, int len, int frame_len)
{
    struct dot11k_beacon_measurement_report* beacon_rep = NULL;
    unsigned char element_len = pframe[len + 1];
    unsigned char element_id;
    unsigned char subelement_len;
    unsigned char subelement_id;
    unsigned short subelements_begin;
    unsigned short subelements_copy_len = 0;
    unsigned short subelements_add = 1;
	unsigned char subelement_len_diff = 0;

    if(pframe[len + 3] == 0)  /*succeed*/
    {
        pstat->rm.measure_result = MEASUREMENT_RECEIVED;
        if(element_len <= 3)
        {
            return len += 2 + element_len;
        }

        if(pstat->rm.beacon_report_num < MAX_BEACON_REPORT)
        {
            beacon_rep = &pstat->rm.beacon_report[pstat->rm.beacon_report_num];
            memset(beacon_rep, 0x00, sizeof(struct dot11k_beacon_measurement_report));
#ifdef RTK_MULTI_AP
			pstat->rm.beacon_report_len[pstat->rm.beacon_report_num] = element_len;
			pstat->rm.beacon_measurement_token[pstat->rm.beacon_report_num] = pframe[len+2];
			pstat->rm.beacon_report_mode[pstat->rm.beacon_report_num] = pframe[len+3];
#endif
            pstat->rm.beacon_report_num++;
        }

        if(beacon_rep)
        {
            beacon_rep->info.op_class = pframe[len + 5];
            beacon_rep->info.channel = pframe[len + 6];
            beacon_rep->info.measure_time_lo = le32_to_cpu(*(unsigned int *)&pframe[len + 7]);
            beacon_rep->info.measure_time_hi = le32_to_cpu(*(unsigned int *)&pframe[len + 11]);
            beacon_rep->info.measure_duration= le16_to_cpu(*(unsigned short *)&pframe[len + 15]);
            beacon_rep->info.frame_info = pframe[len + 17];
            beacon_rep->info.RCPI = pframe[len + 18];
            beacon_rep->info.RSNI = pframe[len + 19];
            memcpy(beacon_rep->info.bssid, pframe + len + 20, MACADDRLEN);
            beacon_rep->info.antenna_id = pframe[len + 26];
            beacon_rep->info.parent_tsf = le32_to_cpu(*(unsigned int *)&pframe[len + 27]);
			DEBUG_INFO("[ROAMING] Receive beacon_report:SUCCESS, CH = %d, OP_CLASS = %d\n", beacon_rep->info.channel, beacon_rep->info.op_class);
        }

        /* parse subelements*/
        len += 31;

        while(len + 2 <= frame_len)
        {
            subelement_id = pframe[len];
            subelement_len = pframe[len + 1];

            if(len + 2 + subelement_len > frame_len)
            {
                break;
            }

            if(subelement_id == _FRAME_BODY_SUBIE_)
            {

                if(len + 14 > frame_len)
                {
                    break;
                }

                subelements_begin = len;
                subelements_copy_len = 14;

                len += 14; // id + len + fixed-length field

                while(len + 2 <= frame_len)
                {
                    element_id = pframe[len];
                    element_len = pframe[len + 1];

                    if(len + 2 + element_len > frame_len)
                    {
                        break;
                    }

                    if(element_id == _MEASUREMENT_REPORT_IE_)
                    {
                        break;
                    }
                    len += 2 + element_len;

                    if(subelements_add)
                    {
                        if(subelements_copy_len + 2 + element_len <= MAX_BEACON_SUBLEMENT_LEN)
                        {
                        	if(subelements_copy_len + 2 + element_len <= (subelement_len + 2)){
                            	subelements_copy_len += 2 + element_len;
                        	}
							else{
								subelement_len_diff = (subelement_len + 2) - subelements_copy_len;
								subelements_copy_len += subelement_len_diff;
								subelements_add = 0;
							}
                        }
                        else
                            subelements_add = 0;
                    }
                }
            }
            else if(subelement_id == _VENDOR_SPEC_IE_)
            {
                len += 2 + subelement_len;
            }
            else
            {
                break;
            }
        }

        if(beacon_rep)
        {
            beacon_rep->subelements_len = subelements_copy_len;
            memcpy(beacon_rep->subelements, pframe + subelements_begin, beacon_rep->subelements_len);
#ifdef ROAMING_SUPPORT
			if(priv->pmib->roamingEntry.roaming_enable)
				rm_fill_beacon_report_to_neighbor_report(priv, pstat, beacon_rep);
#endif
        }
        return len;
    }
    else if(pframe[len + 3] & BIT1)   /*incapable*/
    {
		DEBUG_INFO("[ROAMING] Receive beacon_report:MEASUREMENT_INCAPABLE\n");
        pstat->rm.measure_result = MEASUREMENT_INCAPABLE;
#ifdef RTK_MULTI_AP
		pstat->rm.beacon_report_len[0] = element_len;
		pstat->rm.beacon_measurement_token[0] = pframe[len+2];
		pstat->rm.beacon_report_mode[0] = pframe[len+3];
		pstat->rm.beacon_report_num = 1;
		//rtk_multi_ap_beaconMetricsResponseNotify(pstat);
#endif
        if (timer_pending(&pstat->rm_timer))
            del_timer_sync(&pstat->rm_timer);
    }
    else if(pframe[len + 3] & BIT2)  /*refused*/
    {
		DEBUG_INFO("[ROAMING] Receive beacon_report:MEASUREMENT_REFUSED\n");
        pstat->rm.measure_result = MEASUREMENT_REFUSED;
#ifdef RTK_MULTI_AP
		pstat->rm.beacon_report_len[0] = element_len;
		pstat->rm.beacon_measurement_token[0] = pframe[len+2];
		pstat->rm.beacon_report_mode[0] = pframe[len+3];
		pstat->rm.beacon_report_num = 1;
		//rtk_multi_ap_beaconMetricsResponseNotify(pstat);
#endif		
        if (timer_pending(&pstat->rm_timer))
            del_timer_sync(&pstat->rm_timer);
    }

    return len + element_len + 2;
}




enum MEASUREMENT_RESULT rm_parse_beacon_request(struct rtl8192cd_priv *priv,
        unsigned char *pframe, int offset, int frame_len, unsigned short * interval)
{
    enum MEASUREMENT_RESULT ret = MEASUREMENT_PROCESSING;
    unsigned char sub_element_id;
    unsigned char sub_element_len;
    const OP_CLASS *operating_class;
    const unsigned char*  channel_array;
    int i,j, ap_report_idx = 0, check_bssid;
    struct dot11k_beacon_measurement_req * beacon_req;

    /*check beacon mode*/
    if( pframe[offset + 6] == BEACON_MODE_PASSIVE && priv->pmib->dot11StationConfigEntry.dot11RMBeaconPassiveMeasurementActivated == 0)
    {
        ret = MEASUREMENT_INCAPABLE;
        goto end_parse_beacon_req;
    }
    else if(pframe[offset + 6] == BEACON_MODE_ACTIVE && priv->pmib->dot11StationConfigEntry.dot11RMBeaconActiveMeasurementActivated == 0)
    {
        ret = MEASUREMENT_INCAPABLE;
        goto end_parse_beacon_req;
    }
    else if(pframe[offset + 6] == BEACON_MODE_TABLE && priv->pmib->dot11StationConfigEntry.dot11RMBeaconTableMeasurementActivated == 0)
    {
        ret = MEASUREMENT_INCAPABLE;
        goto end_parse_beacon_req;
    }

    priv->rm.beacon_report_num = 0;
    priv->rm.beacon_send_count = 0;
    beacon_req = &priv->rm.beacon_req;
    memset(beacon_req, 0, sizeof(struct dot11k_beacon_measurement_req));
    beacon_req->op_class =  pframe[offset];
    beacon_req->channel =  pframe[offset+1];
    *interval = beacon_req->random_interval =  le16_to_cpu(*(unsigned short *)&pframe[offset + 2]);
    beacon_req->measure_duration=  le16_to_cpu(*(unsigned short *)&pframe[offset + 4]);
    beacon_req->mode =  pframe[offset + 6];
    memcpy(beacon_req->bssid, pframe + offset + 7, MACADDRLEN);
    beacon_req->report_detail = 2; /*default*/

    /*parse subelements*/
    offset += 13;
    while(offset + 2 < frame_len)
    {
        sub_element_id = pframe[offset];
        sub_element_len = pframe[offset + 1];

        switch(sub_element_id)
        {
            case _SSID_IE_:
                memcpy(beacon_req->ssid, pframe + offset + 2, sub_element_len);
                beacon_req->ssid[sub_element_len] = 0;
                break;
            case _REPORT_DETAIL_SUBIE_: /*report detail*/
                beacon_req->report_detail = pframe[offset + 2];
                break;
            case _REQUEST_IE_:
                if(MAX_REQUEST_IE_LEN < sub_element_len)
                {
                    sub_element_len = MAX_REQUEST_IE_LEN;
                }
                beacon_req->request_ie_len = sub_element_len;
                memcpy(beacon_req->request_ie, pframe + offset + 2, sub_element_len);
                break;
            case _AP_CHANNEL_REPORT_IE_:
                if(ap_report_idx < MAX_AP_CHANNEL_REPORT)
                {
                    i = sub_element_len;
                    if(i > MAX_AP_CHANNEL_NUM+1)
                    {
                        i = MAX_AP_CHANNEL_NUM+1;
                    }
                    beacon_req->ap_channel_report[ap_report_idx].len = i;
                    memcpy(&beacon_req->ap_channel_report[ap_report_idx].op_class, pframe + offset + 2, i);
                    ap_report_idx++;
                }
                break;
            default:
                break;
        }

        offset += 2 + sub_element_len;
    }

    if(beacon_req->mode == BEACON_MODE_TABLE)
    {
        /*table beacon mode do not need to check channel and operating class*/
        /* and do not do measurement as well,  return accumulte beacon information directly*/
        check_bssid = 0;
        if(memcmp(wildcard_bssid, beacon_req->bssid, MACADDRLEN))
        {
            check_bssid = 1;
        }
        for(i = 0; i < priv->rm.beacon_accumulate_num; i++)
        {
            if(check_bssid && memcmp(priv->rm.beacon_accumulate_report[i].info.bssid, beacon_req->bssid, MACADDRLEN))
            {
                continue;
            }

            if(beacon_req->ssid[0] && strcmp(priv->rm.beacon_accumulate_report[i].ssid, beacon_req->ssid))
            {
                continue;
            }

            memcpy(&priv->rm.beacon_report[priv->rm.beacon_report_num].info,
                   &priv->rm.beacon_accumulate_report[i].info,
                   sizeof(struct dot11k_beacon_measurement_report_info));
            priv->rm.beacon_report[priv->rm.beacon_report_num].subelements_len = 0;
            priv->rm.beacon_report_num++;
        }
        
        ret = MEASUREMENT_SUCCEED;
        goto end_parse_beacon_req;
    }

    /*check if operating class & channel is supported*/
    priv->rm.beacon_channel_num = 0;
    if(beacon_req->channel == 255)
    {
        if(ap_report_idx)
        {
            for(i = 0; i < ap_report_idx; i++)
            {
                get_channel_of_ap_report(priv, &beacon_req->ap_channel_report[i]);
            }
        }
        else   /*the beacon reqest do not bring ap channel report,  check the ap channel report in beacon & prob rsp frame*/
        {
            for(i = 0; i < MAX_AP_CHANNEL_REPORT; i++)
            {
                get_channel_of_ap_report(priv, &priv->rm_ap_channel_report[i]);
            }
        }

    }
    else if(beacon_req->channel)
    {
        for(i = 0; i < priv->available_chnl_num; i++)
        {
            if(priv->available_chnl[i] == beacon_req->channel)
            {
                priv->rm.beacon_channel[priv->rm.beacon_channel_num] = beacon_req->channel;
                priv->rm.beacon_channel_num++;
                break;
            }
        }
    }
    else
    {
        operating_class = check_op_class(priv, beacon_req->op_class);
        if(operating_class)
        {
            channel_array = operating_class->channel_array;
            for(i = 1; i <= channel_array[0]; i++)
            {
                for(j = 0; j < priv->available_chnl_num; j++)
                {
                    if(priv->available_chnl[j] == channel_array[i])
                    {
                        if(priv->rm.beacon_channel_num < MAX_BEACON_REQ_CHANNEL)
                        {
                            priv->rm.beacon_channel[priv->rm.beacon_channel_num] = channel_array[i];
                            priv->rm.beacon_channel_num++;
                        }
                        break;
                    }
                }
            }
        }
    }


    if(priv->rm.beacon_channel_num == 0) /*no channel can be scan*/
    {
        ret = MEASUREMENT_REFUSED;
        goto end_parse_beacon_req;
    }


end_parse_beacon_req:
    return ret;
}

enum MEASUREMENT_RESULT  rm_do_beacon_measure(struct rtl8192cd_priv *priv)
{
    struct rtl8192cd_priv *check_priv;
    unsigned char skip = 0;
    int i;

    /* check if other scan procesure is on-going*/
    skip = 0;
    if(priv->ss_req_ongoing || 
       priv->pmib->dot11OperationEntry.opmode & WIFI_SITE_MONITOR || 
       ((OPMODE & WIFI_AP_STATE) && (priv->ext_stats.tx_avarage>>17) > 0)
       )
    {
        skip = 1;
    }
#ifdef MBSSID
    if(skip == 0)
    {
        if ( GET_ROOT(priv)->pmib->miscEntry.vap_enable)
        {
            for (i=0; i<RTL8192CD_NUM_VWLAN; i++)
            {
                check_priv =  GET_ROOT(priv)->pvap_priv[i];
                if (IS_DRV_OPEN(check_priv) &&
                        ( check_priv->ss_req_ongoing || 
                          check_priv->pmib->dot11OperationEntry.opmode & WIFI_SITE_MONITOR || 
                          ((GET_MIB(check_priv))->dot11OperationEntry.opmode & WIFI_AP_STATE && (check_priv->ext_stats.tx_avarage>>17) > 0)
                        )
                   )
                {
                    skip = 1;
                }
            }
        }
    }
#endif

#ifdef UNIVERSAL_REPEATER
    if(skip == 0)
    {
        check_priv =  GET_ROOT(priv)->pvxd_priv;
        if (IS_DRV_OPEN(check_priv) &&
                (check_priv->ss_req_ongoing || check_priv->pmib->dot11OperationEntry.opmode & WIFI_SITE_MONITOR)
           )
        {
            skip = 1;
        }
    }
#endif

    if(skip == 0 && priv->rm.beacon_last_time > 0) {
        if(RTL_JIFFIES_TO_SECOND(jiffies - priv->rm.beacon_last_time) < MIN_BEACON_INTERVAL) {
            skip = 1; 
        }
    }


    if(skip)
    {
        return MEASUREMENT_REFUSED;
    }
    else
    {
        priv->ss_ssidlen = strlen(priv->rm.beacon_req.ssid);
        memcpy(priv->ss_ssid, priv->rm.beacon_req.ssid, priv->ss_ssidlen);
        priv->ss_ssid[priv->ss_ssidlen] = 0;
        priv->ss_req_ongoing = SSFROM_11K_BEACONREQ;
        priv->rm.beacon_last_time = jiffies;        
        start_clnt_ss(priv);
        return MEASUREMENT_PROCESSING;
    }
}

enum MEASUREMENT_RESULT rm_terminate_beacon_measure(struct rtl8192cd_priv *priv)
{
    if(priv->ss_req_ongoing == SSFROM_11K_BEACONREQ)
    {
        if (timer_pending(&priv->ss_timer))
            del_timer_sync(&priv->ss_timer);
        priv->rm.force_stop_ss = 1;
        rtl8192cd_ss_timer((unsigned long)priv);
        priv->rm.force_stop_ss = 0;
        return MEASUREMENT_SUCCEED;
    }
    else
    {
        return MEASUREMENT_UNKNOWN;
    }
}

void rm_beacon_expire(unsigned long task_pstat)
{
    struct stat_info *pstat = (struct stat_info *)task_pstat;
    if(pstat->rm.measure_result == MEASUREMENT_RECEIVED)
    {
        pstat->rm.measure_result = MEASUREMENT_SUCCEED;
    }
    else if(pstat->rm.measure_result == MEASUREMENT_PROCESSING)
    {
         pstat->rm.measure_result = MEASUREMENT_UNKNOWN;
    }
}
void rm_insert_neighbor_report(struct rtl8192cd_priv *priv, struct dot11k_beacon_measurement_req* beacon_req)
{
	struct dot11k_neighbor_report* neighbor_rep = NULL;
	int i, len, empty_slot;
	unsigned char *bssid;
    unsigned int oldest_aging;
    int oldest_idx;
    unsigned char * ssid_ptr;
    int ssid_len;
    int found = 0;
    
	bssid = beacon_req->bssid;
	if(bssid[0] == 0xff && bssid[1] == 0xff && bssid[2] == 0xff && bssid[3] == 0xff && bssid[4] == 0xff && bssid[5] == 0xff)
		return;
    
	/*search for neighbor report*/
    for(i = 0, empty_slot = -1; i < MAX_NEIGHBOR_REPORT; i++)
    {
        if((priv->rm_neighbor_bitmask[i>>3] & (1<<(i&7))) == 0)
        {
            if(empty_slot == -1)
                empty_slot = i;
        }
        else if(0 == memcmp(bssid, priv->rm_neighbor_report[i].bssid, MACADDRLEN)) /*same BSSID*/
        {
        	found = 1;
            break;
        }
    }
    if(i == MAX_NEIGHBOR_REPORT && empty_slot != -1)   /*not found, and has empty slot*/
    {
        i = empty_slot;        
        memcpy(priv->rm_neighbor_report[i].bssid, bssid, MACADDRLEN);
    }
    
    if(i == MAX_NEIGHBOR_REPORT)  /*not found and no empty slot, find the oldest neighbor and replace it*/
    {
    	
	    for(i = 0; i < MAX_NEIGHBOR_REPORT; i++)
	    {
	        if(priv->rm_neighbor_bitmask[i>>3] & (1<<(i&7)))
	        {
	        	/* select oldest entry*/
	            if(oldest_aging < priv->rm_neighbor_info[i].aging) {
	                oldest_aging = priv->rm_neighbor_info[i].aging;
	                oldest_idx = i;
	            }
	        }
	  	}        
        i = oldest_idx;        
        memcpy(priv->rm_neighbor_report[i].bssid, bssid, MACADDRLEN);
    }

	if(found)
	{
		if(priv->rm_neighbor_report[i].channel == beacon_req->channel)
		{
			priv->rm_neighbor_info[i].aging = 0;
			priv->rm_neighbor_info[i].source = 1;
    		priv->rm_neighbor_bitmask[i>>3] |= (1<<(i&7));    
    		return;
		}
	}
    
	priv->rm_neighbor_report[i].bssinfo.value = 0x000E;
    priv->rm_neighbor_report[i].channel = beacon_req->channel;
    priv->rm_neighbor_report[i].op_class = rm_get_op_class(priv, beacon_req->channel);
    priv->rm_neighbor_report[i].phytype = 0;

    priv->rm_neighbor_report[i].bssinfo.field.cap_spectrum = 1;
    priv->rm_neighbor_report[i].bssinfo.field.cap_qos = 1;
    priv->rm_neighbor_report[i].bssinfo.field.cap_apsd = 1;
    priv->rm_neighbor_report[i].bssinfo.field.cap_rm = 1;      
    priv->rm_neighbor_report[i].bssinfo.field.cap_delay_ba = 1;
    priv->rm_neighbor_report[i].bssinfo.field.cap_im_ba = 1;

    priv->rm_neighbor_info[i].ssid[ssid_len] = 0;
    priv->rm_neighbor_info[i].aging = 0;
    priv->rm_neighbor_info[i].bssload.sta_count = 0;
    priv->rm_neighbor_info[i].bssload.channel_utilization = 0;
    priv->rm_neighbor_info[i].source = 1;
    priv->rm_neighbor_bitmask[i>>3] |= (1<<(i&7));    
}
int rm_beacon_measurement_request(struct rtl8192cd_priv *priv, unsigned char *macaddr,
                                  struct dot11k_beacon_measurement_req* beacon_req)
{
    int measure_time;
    int ret = -1;
    struct stat_info *pstat;
    const OP_CLASS* op_class;
    int i, total_channel_num = 0;

#ifdef SDIO_AP_OFFLOAD
    ap_offload_deactivate(priv, OFFLOAD_PROHIBIT_RADIO_MEASURE);
#endif

    if(priv->pmib->dot11StationConfigEntry.dot11RadioMeasurementActivated &&
            (priv->pmib->dot11StationConfigEntry.dot11RMBeaconActiveMeasurementActivated ||
             priv->pmib->dot11StationConfigEntry.dot11RMBeaconPassiveMeasurementActivated))
    {
        pstat = get_stainfo(priv, macaddr);
        if(pstat)
        {

            if (pstat->expire_to == 0)
                goto beacon_req_fail;

            /* check if  beacon measurement is on-going*/
            if(pstat->rm.measure_result == MEASUREMENT_PROCESSING)
                goto beacon_req_fail;

            /* check if   measurement mode is supported*/
            if(beacon_req->mode != BEACON_MODE_PASSIVE && beacon_req->mode != BEACON_MODE_ACTIVE &&
                    beacon_req->mode != BEACON_MODE_TABLE)
                goto beacon_req_fail;

            if((pstat->rm.rm_cap[0] & 0x10) && beacon_req->mode == BEACON_MODE_PASSIVE &&
                    priv->pmib->dot11StationConfigEntry.dot11RMBeaconPassiveMeasurementActivated == 0)
            {
                goto beacon_req_fail;
            }
            if((pstat->rm.rm_cap[0] & 0x20) && beacon_req->mode == BEACON_MODE_ACTIVE &&
                    priv->pmib->dot11StationConfigEntry.dot11RMBeaconActiveMeasurementActivated == 0)
            {
                goto beacon_req_fail;
            }

            if((pstat->rm.rm_cap[0] & 0x40) && beacon_req->mode == BEACON_MODE_TABLE &&
                    priv->pmib->dot11StationConfigEntry.dot11RMBeaconTableMeasurementActivated == 0)
            {
                goto beacon_req_fail;
            }
            
            /* check if  report_details is supported*/
            if(beacon_req->report_detail > 2) {
                goto beacon_req_fail;
            }

            if(beacon_req->channel == 0)
            {
                /* check if operating class is supported*/
                if((op_class = check_op_class(priv, beacon_req->op_class)) == NULL)
                {
                    goto beacon_req_fail;
                }
                total_channel_num = op_class->channel_array[0];
            }
            else if(beacon_req->channel == 255)
            {
                for(i = 0; i < MAX_AP_CHANNEL_REPORT; i++)
                {
                    /* check if ap channel report is supported*/
                    if(beacon_req->ap_channel_report[i].len)
                    {
                        if(check_ap_channel_report(priv, &beacon_req->ap_channel_report[i]))
                            goto beacon_req_fail;
                        total_channel_num += beacon_req->ap_channel_report[i].len-1;
                    }
                }
            }
            else
                total_channel_num = 1;

            memcpy(&pstat->rm.beacon_req, beacon_req, sizeof(struct dot11k_beacon_measurement_req));
            ret = issue_beacon_measurement_request(priv, pstat, &pstat->rm.beacon_req);
            if(ret == 0)   /*issue beacon measurement request succeed*/
            {
                pstat->rm.beacon_report_num = 0;
                pstat->rm.measure_result = MEASUREMENT_PROCESSING;
                measure_time = pstat->rm.beacon_req.measure_duration * total_channel_num;

                if(total_channel_num == 1) {
                    measure_time += pstat->rm.beacon_req.random_interval + 1000; //tolerance
                }
                else
                    measure_time += pstat->rm.beacon_req.random_interval + 7000; //tolerance

                if((pstat->state & (WIFI_SLEEP_STATE | WIFI_ASOC_STATE)) ==
                            (WIFI_SLEEP_STATE | WIFI_ASOC_STATE)) {
                    measure_time += 3000; /*if sta is in sleep mode, wait more time*/
                }                    
            #if defined(CONFIG_USB_HCI)
                if (GET_HCI_TYPE(priv) == RTL_HCI_USB) {
                measure_time += 3000;
                }
            #endif

                mod_timer(&pstat->rm_timer, jiffies + RTL_MILISECONDS_TO_JIFFIES(measure_time));
            }
        }
    }

beacon_req_fail:
#ifdef SDIO_AP_OFFLOAD
    ap_offload_activate(priv, OFFLOAD_PROHIBIT_RADIO_MEASURE);
#endif

    return ret;
}

int rm_get_beacon_report(struct rtl8192cd_priv *priv, unsigned char *macaddr, unsigned char **result_buf2)
{
    int len = -1;
    struct stat_info *pstat;
    unsigned char *result_buf;

#ifdef SDIO_AP_OFFLOAD
    ap_offload_deactivate(priv, OFFLOAD_PROHIBIT_RADIO_MEASURE);
#endif

    if(priv->pmib->dot11StationConfigEntry.dot11RadioMeasurementActivated &&
            (priv->pmib->dot11StationConfigEntry.dot11RMBeaconActiveMeasurementActivated ||
             priv->pmib->dot11StationConfigEntry.dot11RMBeaconPassiveMeasurementActivated))
    {
        pstat = get_stainfo(priv, macaddr);
        if(pstat)
        {
        	*result_buf2 = kmalloc((pstat->rm.beacon_report_num * sizeof(struct dot11k_beacon_measurement_report) + 2), GFP_ATOMIC);
        	if (*result_buf2 == NULL)
        	{
				panic_printk("Fail allocate memory for Beacon Measurement Report\n");
				return len;
        	}
        	result_buf = *result_buf2;
			if(pstat->rm.measure_result == MEASUREMENT_RECEIVED)
            	*result_buf = MEASUREMENT_SUCCEED;
			else
				*result_buf = pstat->rm.measure_result;
				
            len = 1;

            if(pstat->rm.measure_result == MEASUREMENT_SUCCEED || pstat->rm.beacon_report_num > 0)
            {
                *(result_buf + len) = pstat->rm.beacon_report_num;
                len++;
                memcpy(result_buf + len, pstat->rm.beacon_report, pstat->rm.beacon_report_num * sizeof(struct dot11k_beacon_measurement_report));
                len += pstat->rm.beacon_report_num * sizeof(struct dot11k_beacon_measurement_report);

#ifdef RTK_SMART_ROAMING
				pstat->rm.neighbor_ap_num = pstat->rm.beacon_report_num;
#endif
#ifdef CONFIG_IEEE80211V
				pstat->rcvNeighborReport = TRUE;
				if(WNM_ENABLE && pstat->bssTransSupport && priv->pmib->wnmEntry.Is11kDaemonOn)
					pstat->rcvNeighborReport = TRUE;
#endif
				if(pstat->rm.beacon_report_num)
					DEBUG_INFO("====Beacon Report====\n");
				int i;
				for(i = 0; i < pstat->rm.beacon_report_num; i++)
				{
					DEBUG_INFO("CH%d\tBSSID %02X%02X%02X%02X%02X%02X\tRCPI %d\t/RSNI %d\n", pstat->rm.beacon_report[i].info.channel,
						pstat->rm.beacon_report[i].info.bssid[0],pstat->rm.beacon_report[i].info.bssid[1],
						pstat->rm.beacon_report[i].info.bssid[2],pstat->rm.beacon_report[i].info.bssid[3],pstat->rm.beacon_report[i].info.bssid[4],pstat->rm.beacon_report[i].info.bssid[5],
						pstat->rm.beacon_report[i].info.RCPI,pstat->rm.beacon_report[i].info.RSNI);
				}
            }

            if(pstat->rm.measure_result == MEASUREMENT_SUCCEED ||
                    pstat->rm.measure_result == MEASUREMENT_INCAPABLE ||
                    pstat->rm.measure_result == MEASUREMENT_REFUSED)
            {
                pstat->rm.measure_result = MEASUREMENT_UNKNOWN;
            }
        }
    }

#ifdef SDIO_AP_OFFLOAD
    ap_offload_activate(priv, OFFLOAD_PROHIBIT_RADIO_MEASURE);
#endif

    return len;
}

int rm_collect_bss_info(struct rtl8192cd_priv *priv, struct rx_frinfo *pfrinfo)
{
    int i, len, element_len;
    unsigned char *pframe, *p, *bssid;
    struct dot11k_beacon_measurement_report * beacon_rep;
    struct dot11k_beacon_measurement_req * request;

    pframe = get_pframe(pfrinfo);
    bssid = GetAddr3Ptr(pframe);

    request = &priv->rm.beacon_req;
    /* checking BSSID */
    if(memcmp(wildcard_bssid, request->bssid, MACADDRLEN))
    {
        if(memcmp(bssid, request->bssid, MACADDRLEN))
        {
            return 0;
        }
    }

    /* checking SSID */
    if (priv->ss_ssidlen > 0)
    {
        p = get_ie(pframe + WLAN_HDR_A3_LEN + _BEACON_IE_OFFSET_, _SSID_IE_, &len,
                   pfrinfo->pktlen - WLAN_HDR_A3_LEN - _BEACON_IE_OFFSET_);
        if ((p == NULL) ||		// NULL AP case 1
                (len == 0) ||		// NULL AP case 2
                (*(p+2) == '\0'))	// NULL AP case 3 (like 8181/8186)
        {
            return 0;
        }

        if (priv->ss_ssidlen != len || memcmp(priv->ss_ssid, p+2, len))
            return 0;
    }

    /*search for beacon report*/
    for(i = 0; i < priv->rm.beacon_report_num; i++)
    {
        if(memcmp(bssid, request->bssid, MACADDRLEN) == 0)
            break;
    }

    if(i >= MAX_BEACON_REPORT)
    {
        return -1; /* beacon report full*/
    }

    beacon_rep = &priv->rm.beacon_report[i];
    if(i >= priv->rm.beacon_report_num)
    {
        priv->rm.beacon_report_num++;
        memset(beacon_rep, 0x00, sizeof(struct dot11k_beacon_measurement_report));
        memset(priv->rm.beacon_ssid[i], 0x00, WLAN_SSID_MAXLEN+1);
        memcpy(beacon_rep->info.bssid, bssid, MACADDRLEN);
        p = get_ie(pframe + WLAN_HDR_A3_LEN + _BEACON_IE_OFFSET_, _SSID_IE_, &len,
                   pfrinfo->pktlen - WLAN_HDR_A3_LEN - _BEACON_IE_OFFSET_);
        if(p)
        {
            memcpy(priv->rm.beacon_ssid[i], p+2, len);
            priv->rm.beacon_ssid[i][len] = 0;
        }
        beacon_rep->info.measure_time_hi = priv->rm.measure_time_hi;
        beacon_rep->info.measure_time_lo = priv->rm.measure_time_lo;
        beacon_rep->info.measure_duration = request->measure_duration;
    }

    if(request->channel == 255)
        beacon_rep->info.op_class = get_op_class_from_apreport(priv, priv->site_survey->ss_channel);
    else
        beacon_rep->info.op_class = request->op_class;
    beacon_rep->info.channel = priv->site_survey->ss_channel;
    beacon_rep->info.frame_info = 0;
    beacon_rep->info.RCPI = pfrinfo->rf_info.rssi<<1;
    beacon_rep->info.RSNI = 0xFF;
    beacon_rep->info.antenna_id = 0;
    beacon_rep->info.parent_tsf = RTL_R32(TSFTR);

    beacon_rep->subelements_len = 0;
    if(request->report_detail == 1 || request->report_detail == 2)
    {
        beacon_rep->subelements[0] = _FRAME_BODY_SUBIE_;
        beacon_rep->subelements_len = 2;

        /*copy fixed-lengh field*/
        memcpy(beacon_rep->subelements + beacon_rep->subelements_len, pframe + WLAN_HDR_A3_LEN, _BEACON_IE_OFFSET_);
        beacon_rep->subelements_len += _BEACON_IE_OFFSET_;

        if(request->report_detail == 1)
        {
            /*copy requested ie*/
            for(i = 0; i < request->request_ie_len; i++)
            {
                p = get_ie(pframe + WLAN_HDR_A3_LEN + _BEACON_IE_OFFSET_,
                           request->request_ie[i], &len,
                           pfrinfo->pktlen - WLAN_HDR_A3_LEN - _BEACON_IE_OFFSET_);
                if (p != NULL)
                {
                    len += 2;
                    if(beacon_rep->subelements_len + len <= MAX_BEACON_SUBLEMENT_LEN)
                    {
                        memcpy(beacon_rep->subelements + beacon_rep->subelements_len, p, len);
                        beacon_rep->subelements_len += len;
                    }
                }
            }
        }
        else
        {
            /*copy all ie if possible*/
            len = WLAN_HDR_A3_LEN + _BEACON_IE_OFFSET_;
            while(len + 2 <= pfrinfo->pktlen)
            {

                element_len = pframe[len + 1] + 2;
                if(beacon_rep->subelements_len + element_len <= MAX_BEACON_SUBLEMENT_LEN)
                {
                    memcpy(beacon_rep->subelements + beacon_rep->subelements_len, pframe + len, element_len);
                    beacon_rep->subelements_len += element_len;

                }
                else
                {
                    break;
                }
                len += element_len;
            }
        }

        beacon_rep->subelements[1] = beacon_rep->subelements_len - 2;
    }

}

void rm_beacon_done(struct rtl8192cd_priv *priv)
{
    int i,j;
    unsigned char accumulate_bitmask[MAX_BEACON_REPORT/8+1];
    unsigned char recv_beacon_bitmask[MAX_BEACON_REPORT/8+1];
    unsigned int  measure_time_hi;
    unsigned int  measure_time_lo;
    int index, report_full = 0;

    /*accumulate beacon report*/
    memset(accumulate_bitmask, 0, MAX_BEACON_REPORT/8+1);
    memset(recv_beacon_bitmask, 0, MAX_BEACON_REPORT/8+1);
    for(i = 0; i < priv->rm.beacon_report_num; i++)
    {
        for(j = 0; j < priv->rm.beacon_accumulate_num; j++)
        {
            if(0 == memcmp(priv->rm.beacon_report[i].info.bssid, priv->rm.beacon_accumulate_report[j].info.bssid, MACADDRLEN))
            {
                break;
            }
        }

        if(j < priv->rm.beacon_accumulate_num || j < MAX_BEACON_REPORT)
        {
            recv_beacon_bitmask[i>>3] |= (1 << (i&7));
            accumulate_bitmask[j>>3] |= (1 << (j&7));
            memcpy(&priv->rm.beacon_accumulate_report[j].info, &priv->rm.beacon_report[i].info, sizeof(struct dot11k_beacon_measurement_report_info));
            strcpy(priv->rm.beacon_accumulate_report[j].ssid, priv->rm.beacon_ssid[i]);
            if(j >= priv->rm.beacon_accumulate_num)
            {
                priv->rm.beacon_accumulate_num++;
            }
        }
        else
        {
            report_full = 1;
        }
    }

    if(report_full)
    {
        for(i = 0; i < priv->rm.beacon_report_num; i++)
        {
            if((recv_beacon_bitmask[i>>3] & (1 << (i&7))) == 0)
            {
                index = -1;
                measure_time_hi = 0xFFFFFFFF;
                measure_time_lo = 0xFFFFFFFF;
                for(j = 0; j < priv->rm.beacon_accumulate_num; j++)
                {
                    if((accumulate_bitmask[j>>3] & (1 << (j&7))) == 0)
                    {
                        if(priv->rm.beacon_accumulate_report[j].info.measure_time_hi < measure_time_hi ||
                                (priv->rm.beacon_accumulate_report[j].info.measure_time_hi == measure_time_hi &&
                                 priv->rm.beacon_accumulate_report[j].info.measure_time_lo < measure_time_lo))
                        {
                            measure_time_hi = priv->rm.beacon_accumulate_report[j].info.measure_time_hi;
                            measure_time_lo = priv->rm.beacon_accumulate_report[j].info.measure_time_lo;
                            index = j;
                        }
                    }
                }
                if(index > 0)
                {
                    accumulate_bitmask[index>>3] |= (1 << index&7);
                    memcpy(&priv->rm.beacon_accumulate_report[index].info, &priv->rm.beacon_report[i].info, sizeof(struct dot11k_beacon_measurement_report_info));
                    strcpy(priv->rm.beacon_accumulate_report[j].ssid, priv->rm.beacon_ssid[i]);
                }
            }
        }
    }


    rm_done(priv, MEASUREMENT_TYPE_BEACON, priv->rm.force_stop_ss?0:1);

}

unsigned char * construct_beacon_report_ie(struct rtl8192cd_priv *priv, unsigned char *pbuf, unsigned int *frlen,
        unsigned char token, unsigned char *full)
{
    unsigned char temp[255];
    struct dot11k_beacon_measurement_report *report;

    *full = 0;
    if(priv->rm.beacon_report_num == 0)
    {
        if(*frlen + 5 > MAX_REPORT_FRAME_SIZE)
        {
            *full = 1;
        }
        else
        {
            temp[0] = token;
            temp[1] = 0;
            temp[2] = MEASUREMENT_TYPE_BEACON;
            pbuf = set_ie(pbuf, _MEASUREMENT_REPORT_IE_, 3, temp, frlen);
        }
    }
    else
    {
        while(priv->rm.beacon_send_count < priv->rm.beacon_report_num &&
              *frlen + 31 + priv->rm.beacon_report[priv->rm.beacon_send_count].subelements_len <= MAX_REPORT_FRAME_SIZE
             )
        {
            temp[0] = token;
            temp[1] = 0; //mode
            temp[2] = MEASUREMENT_TYPE_BEACON;

            report = &priv->rm.beacon_report[priv->rm.beacon_send_count];
            temp[3] = report->info.op_class;
            temp[4] = report->info.channel;
            *(unsigned int *)(temp + 5) = cpu_to_le32(report->info.measure_time_lo);
            *(unsigned int *)(temp + 9) = cpu_to_le32(report->info.measure_time_hi);
            *(unsigned short *)(temp + 13) = cpu_to_le16(report->info.measure_duration);
            temp[15] = report->info.frame_info;
            temp[16] = report->info.RCPI;
            temp[17] = report->info.RSNI;
            memcpy(temp + 18, report->info.bssid, MACADDRLEN);
            temp[24] = report->info.antenna_id;
            *(unsigned int *)(temp + 25) = cpu_to_le32(report->info.parent_tsf);
            memcpy(temp + 29, report->subelements, report->subelements_len);
            pbuf = set_ie(pbuf, _MEASUREMENT_REPORT_IE_, 29 + report->subelements_len, temp, frlen);

            priv->rm.beacon_send_count++;
        }

        if(priv->rm.beacon_send_count < priv->rm.beacon_report_num)
        {
            *full = 1;
        }
    }

    return pbuf;

}


unsigned char *construct_ap_channel_rep_ie(struct rtl8192cd_priv *priv, unsigned char	*pbuf, unsigned int *frlen)
{
    int i;
    for(i = 0; i < MAX_AP_CHANNEL_REPORT; i++)
    {
        if(priv->rm_ap_channel_report[i].len)
        {
            pbuf = set_ie(pbuf, _AP_CHANNEL_REPORT_IE_, 
                priv->rm_ap_channel_report[i].len, 
                &priv->rm_ap_channel_report[i].op_class, frlen);
        }
    }
    return pbuf;
}





#ifdef CLIENT_MODE
void rm_parse_ap_channel_report(struct rtl8192cd_priv *priv, unsigned char *pframe, int frame_len)
{
    int i = 0;
    int len;
    unsigned char *p = pframe;

    for (;;)
    {
        p = get_ie(p, _AP_CHANNEL_REPORT_IE_, &len, frame_len - (p - pframe));
        if (p != NULL)
        {
            if(len > MAX_AP_CHANNEL_NUM+1)
            {
                len = MAX_AP_CHANNEL_NUM+1;
            }
            priv->rm_ap_channel_report[i].len = len;
            memcpy(&priv->rm_ap_channel_report[i].op_class, p + 2, len);
            i++;
        }
        else
            break;
        if(i >= MAX_AP_CHANNEL_REPORT)
            break;
        p = p + len + 2;
    }

    for(; i < MAX_AP_CHANNEL_REPORT; i++)
    {
        priv->rm_ap_channel_report[i].len = 0;
    }    
}


#endif


#ifdef CONFIG_RTL_PROC_NEW
int rtl8192cd_proc_ap_channel_report_read(struct seq_file *s, void *data)
#else
int rtl8192cd_proc_ap_channel_report_read(char *buf, char **start, off_t offset,
        int length, int *eof, void *data)
#endif
{
    struct net_device *dev = PROC_GET_DEV();
    struct rtl8192cd_priv *priv = GET_DEV_PRIV(dev);
    int pos = 0;
    int i,j;
    PRINT_ONE(" -- AP CHANNEL REPORT info -- ", "%s", 1);
    for (i = 0 ; i < MAX_AP_CHANNEL_REPORT; i++)
    {
        if(priv->rm_ap_channel_report[i].len)
        {
            PRINT_ONE("  Operating Class:", "%s", 0);
            PRINT_ONE(priv->rm_ap_channel_report[i].op_class, "%d", 1);
            PRINT_ONE("      Channel List:", "%s", 0);
            for(j = 0; j < priv->rm_ap_channel_report[i].len-1; j++)
            {
                PRINT_ONE(priv->rm_ap_channel_report[i].channel[j], "%d ", 0);
            }
            PRINT_ONE("", "%s", 1);

        }
    }


    return pos;


}

#ifdef __ECOS
int rtl8192cd_proc_ap_channel_report_write(char *tmp, void *data)
#else
int rtl8192cd_proc_ap_channel_report_write(struct file *file, const char *buffer,
        unsigned long count, void *data)
#endif
{

#ifdef __ECOS
    return 0;
#else
    struct net_device *dev = (struct net_device *)data;
    struct rtl8192cd_priv *priv = GET_DEV_PRIV(dev);
    unsigned char error_code = 0;
    char * tokptr;
    int command = 0;
    int empty_slot;
    int i;
    char tmp[50];
    char *tmpptr;
    struct dot11k_ap_channel_report report;

    if((OPMODE & WIFI_AP_STATE) == 0)
    {
        error_code = 1;
        goto end;
    }
    if (count < 2 || count >= 50)
        return -EFAULT;

    if (buffer == NULL || copy_from_user(tmp, buffer, count))
        return -EFAULT;

    tmp[count] = 0;

    tmpptr = tmp;
    tokptr = strsep((char **)&tmpptr, " ");
    if(!memcmp(tokptr, "add", 3))
        command = 1;
    else if(!memcmp(tokptr, "del", 3))
        command = 2;

    if(command)
    {
        tokptr = strsep((char **)&tmpptr," ");
        report.op_class= _atoi(tokptr, 10);
        if(report.op_class > 0)
        {
            if(command == 1)   /*add*/
            {

                i = 0;
                while(i < MAX_AP_CHANNEL_NUM)
                {
                    tokptr = strsep((char **)&tmpptr," ");
                    if(tokptr)
                    {
                        report.channel[i] = _atoi(tokptr, 10);
                        if(report.channel[i] == 0)
                            break;
                        i++;
                    }
                    else
                        break;
                }
                report.len = i+1;

                if(check_ap_channel_report(priv, &report))
                {
                    error_code = 2;
                    goto end;
                }

                for(i = 0, empty_slot = -1; i < MAX_AP_CHANNEL_REPORT; i++)
                {
                    if(priv->rm_ap_channel_report[i].len == 0)
                    {
                        if(empty_slot == -1)
                            empty_slot = i;
                    }
                    else if(priv->rm_ap_channel_report[i].op_class == report.op_class)
                    {
                        break;
                    }
                }
                if(i == MAX_AP_CHANNEL_REPORT && empty_slot != -1)   /*not found*/
                {
                    i = empty_slot;
                }

                if(i == MAX_AP_CHANNEL_REPORT)  /*not found and no empty slot*/
                {
                    error_code = 3;
                    goto end;
                }

                memcpy(&priv->rm_ap_channel_report[i], &report, sizeof(struct dot11k_ap_channel_report));
            }
            else if(command == 2)  /*delete*/
            {
                for(i = 0; i < MAX_AP_CHANNEL_REPORT; i++)
                {
                    if(priv->rm_ap_channel_report[i].len > 0 && priv->rm_ap_channel_report[i].op_class == report.op_class)
                    {
                        priv->rm_ap_channel_report[i].len = 0;
                        break;
                    }
                }
            }
        }
        else
        {
            error_code = 2;
            goto end;
        }
    }
    else
    {
        error_code = 1;
        goto end;
    }

end:
    if(error_code == 1)
        panic_printk("\nwarning: invalid command!\n");
    else if(error_code == 2)
        panic_printk("\nwarning: invalid operating class!\n");
    else if(error_code == 3)
        panic_printk("\nwarning: ap channel report table full!\n");
    return count;
#endif
}

#endif
