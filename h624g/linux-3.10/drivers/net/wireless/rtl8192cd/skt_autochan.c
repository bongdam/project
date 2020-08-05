#ifdef __KERNEL__
#include <linux/module.h>
#include <linux/list.h>
#include <linux/random.h>
#else
#include <memory.h>
#include <string.h>
#endif

#include "skt_autochan.h"

#define SIDEBAND_INTERFERENCE_5G -30 // dBm
#define MAX_INT32 0x7fffffff;

#define MAX_2G_CHAN_NUM 13
#define MAX_5G_CHAN_NUM 19
#define MAX_CHAN_NUM MAX_5G_CHAN_NUM

struct chan_intf_t {
	unsigned int chan;
	unsigned int val;
	unsigned int util_time;

	unsigned int flag40;
	unsigned int flag80;

	unsigned int sum20_org;
	unsigned int sum20;
	unsigned int sum40;
	unsigned int sum80;
};

struct chan_sel_t {
	struct chan_intf_t intf_data[MAX_CHAN_NUM];
	unsigned int chan_num;
	unsigned int intf_sum;
	unsigned int intf_sum40;
	unsigned int util_time_max;
	unsigned int is_5g;
	unsigned int block_5g_bc_band;
};

struct chan_desc_t {
	unsigned int chan;
	unsigned int flag40;	// mark if 40M bw channel start
	unsigned int flag80;	// mark if 80M bw channel start
};

struct rssi_score_t {
	int rssi;
	int score;
};


static struct chan_desc_t chan5_avail[MAX_5G_CHAN_NUM] = {
	{36,  1, 1},
	{40,  0, 0},
	{44,  1, 0},
	{48,  0, 0},
	{52,  1, 1},
	{56,  0, 0},
	{60,  1, 0},
	{64,  0, 0},
	{100, 1, 1},
	{104, 0, 0},
	{108, 1, 0},
	{112, 0, 0},
	{116, 1, 0},
	{120, 0, 0},
	{124, 0, 0},
	{149, 1, 1},
	{153, 0, 0},
	{157, 1, 0},
	{161, 0, 0},
};

static struct chan_desc_t chan2_avail[MAX_2G_CHAN_NUM] = {
	{1,  1, 0},
	{2,  1, 0},
	{3,  1, 0},
	{4,  1, 0},
	{5,  1, 0},
	{6,  1, 0},
	{7,  1, 0},
	{8,  1, 0},
	{9,  1, 0},
	{10, 0, 0},
	{11, 0, 0},
	{12, 0, 0},
	{13, 0, 0},
};

static struct rssi_score_t _rssi_score_2g[] = {
	//{-45, 3},
	{-65, 2},
	{-85, 1},
	{0, 0},
};

static struct rssi_score_t _rssi_score_5g[] = {
	{-65, 2},
	{-85, 1},
	{0, 0},
};

/* signal level per channel distence */
/*                                0    1    2    3    4    5    6    7    8    9   10   11   12   13 */
static int ch_dist_mask_2g_20m[]={0,   0,   0, -15, -30, -30, -99, -99, -99, -99, -99, -99, -99, -99};
static int ch_dist_mask_2g_40m[]={0,   0,   0,   0,   0, -15, -15, -15, -30, -30, -30, -30, -99, -99};

static void chan_sel_init(struct chan_sel_t *csel, int is_5g, int block_5g_bc_band)
{
	int i;

	memset(csel, 0, sizeof(struct chan_sel_t));

	if (is_5g) {
		csel->is_5g = 1;
		csel->chan_num = MAX_5G_CHAN_NUM;
		for (i=0; i<MAX_5G_CHAN_NUM; i++) {
			csel->intf_data[i].chan = chan5_avail[i].chan;
			csel->intf_data[i].flag40 = chan5_avail[i].flag40;
			csel->intf_data[i].flag80 = chan5_avail[i].flag80;
		}
		csel->block_5g_bc_band = block_5g_bc_band;
	} else {
		csel->chan_num = MAX_2G_CHAN_NUM;
		for (i=0; i<MAX_2G_CHAN_NUM; i++) {
			csel->intf_data[i].chan = chan2_avail[i].chan;
			csel->intf_data[i].flag40 = chan2_avail[i].flag40;
		}
	}
	csel->util_time_max = 100;
}

static inline int rssi_dist_2g(int *d_tbl, int rssi, int d)
{
	if ((d<0) || (d>13)) 
		return -99;
	return (rssi + d_tbl[d]);
}

static inline int rssi_to_score(int rssi, struct rssi_score_t *tbl)
{
	int i;

	for (i=0;tbl[i].rssi!=0;i++)
		if (rssi >= tbl[i].rssi)
			return tbl[i].score;

	return 0;
}

static void chan_sel_intf_add_score(struct chan_sel_t *csel, int chan, int score)
{
	int i;

	for (i=0; i<csel->chan_num; i++) {
		if (chan==csel->intf_data[i].chan) {
			csel->intf_data[i].val += score;
			break;
		} else if (chan < csel->intf_data[i].chan) {
			// not found
			break;
		}
	}
}

static void chan_sel_util_time_add(struct chan_sel_t *csel, int chan, int util_time)
{
	int i;

	for (i=0; i<csel->chan_num; i++) {
		if (chan==csel->intf_data[i].chan) {
			if (util_time > csel->util_time_max)
				util_time = csel->util_time_max;
			csel->intf_data[i].util_time = util_time;
			break;
		} else if (chan < csel->intf_data[i].chan) {
			// not found
			break;
		}
	}
}

static void chan_sel_intf_calc_5g(struct chan_sel_t *csel, unsigned int *chan, int num_chan, int rssi)
{
	int i;
	int offset;

	for (i=0;i<num_chan;i++) {
		chan_sel_intf_add_score(csel, chan[i], rssi_to_score(rssi, _rssi_score_5g));
		// num_chan value must be 1 or 2 or 4. So, offset value is 4 or 8 or 16.
		offset = num_chan*4;
		chan_sel_intf_add_score(csel, chan[i]+offset, rssi_to_score(rssi+SIDEBAND_INTERFERENCE_5G, _rssi_score_5g));
		chan_sel_intf_add_score(csel, chan[i]-offset, rssi_to_score(rssi+SIDEBAND_INTERFERENCE_5G, _rssi_score_5g));
	}
}

static void chan_sel_intf_calc_2g(struct chan_sel_t *csel, unsigned int *chan, int num_chan, int rssi)
{
	int c;
	int *d_tbl;
	int i;
	
	if (num_chan==2) {
		c = ((chan[0]<chan[1]) ? chan[0]:chan[1]) + 2; // c contains center channel
		d_tbl = ch_dist_mask_2g_40m;
	} else {
		c = chan[0];
		d_tbl = ch_dist_mask_2g_20m;
	}

	chan_sel_intf_add_score(csel, c, rssi_to_score(rssi_dist_2g(d_tbl, rssi, 0), _rssi_score_2g));
	for (i=1;i<=13;i++) {
		chan_sel_intf_add_score(csel, c+i, rssi_to_score(rssi_dist_2g(d_tbl, rssi, i), _rssi_score_2g));
		chan_sel_intf_add_score(csel, c-i, rssi_to_score(rssi_dist_2g(d_tbl, rssi, i), _rssi_score_2g));
	}
}

static void chan_sel_intf_calc(struct chan_sel_t *csel, unsigned int *chan, int num_chan, int rssi)
{
	if (csel->is_5g)
		chan_sel_intf_calc_5g(csel, chan, num_chan, rssi);
	else
		chan_sel_intf_calc_2g(csel, chan, num_chan, rssi);
}


static void chan_sel_util_calc(struct chan_sel_t *csel, unsigned int *chan, int num_chan, int util_time)
{
	int i;

	for (i = 0; i < num_chan; i++) {
		chan_sel_util_time_add(csel, chan[i], util_time);
	}
}

static inline int chan_selectable(int chan, int num_chan, int block_5g_bc_band)
{
	switch (chan) {
		case 8:
		case 9:
			if (num_chan==1)
				return 1;	// selectable
			else 
				return 0;
		case 12:
		case 13:
			return 0;	// not selectable
		
		case 52:
		case 56:
		case 60:
		case 64:
		case 100:
		case 104:
		case 108:
		case 112:
		case 116:
		case 120:
		case 124:
		case 128:
			if (block_5g_bc_band)
				return 0;
			else 
				return 1;
	}
	return 1;	// selectable
}

static unsigned int get_manual_utiltime(struct chan_intf_t *intf_data, unsigned int max)
{
    unsigned int ret = 0;

    switch (intf_data->chan) {
        /* When channel selection mode is auto, we set fake util time. 
         * Because we want to select channel in front of channel table.(44 or 48 ch) */
		case 36:
		case 40:
            ret = max / 2;
            break;
    }

    if ((ret > 0) && (ret+intf_data->util_time) > max)
        ret = max - (intf_data->util_time);

    return ret;
}

void chan_sel_select(struct chan_sel_t *csel, struct csel_result_t *res)
{
	int i,j;
	int min20, min40, min80;
	int min20_ctrl, min40_ctrl, min80_ctrl;
	int i40, i80;

	memset(res, 0, sizeof(struct csel_result_t));

	csel->intf_sum = 0;
	for (i=0;i<csel->chan_num;i++)
		csel->intf_sum += csel->intf_data[i].val;
	
	csel->intf_sum40 = 0;
	if (csel->is_5g) {
		csel->intf_sum40 = csel->intf_sum;
	} else {
		// for 2g, val will be double counted between ch5 and ch9
		for (i=0;i<csel->chan_num;i++) {
			if ((csel->intf_data[i].chan>=5)&&(csel->intf_data[i].chan<=9))
				csel->intf_sum40 += csel->intf_data[i].val*2;
			else
				csel->intf_sum40 += csel->intf_data[i].val;
		}
	}
  
    if (csel->intf_sum == 0)
    	csel->intf_sum = 1;

#define ROUNDUP(x,d) ((((x)%(d)) >= ((d)/2))?1:0)

    //Orignal expression for getting channel selection score.
#if 0
	// get normalized sum for 20M BW
	for (i=0;i<csel->chan_num;i++) {
		csel->intf_data[i].sum20_org = 
			  csel->intf_data[i].val 
            + (csel->intf_data[i].util_time * csel->intf_sum)/csel->util_time_max 
			+ ROUNDUP(csel->intf_data[i].util_time * csel->intf_sum, csel->util_time_max);	// round-up
		csel->intf_data[i].sum20 = 
			  csel->intf_data[i].val 
            + ((csel->intf_data[i].util_time+get_manual_utiltime(&csel->intf_data[i], csel->util_time_max)) * csel->intf_sum)/csel->util_time_max 
			+ ROUNDUP((csel->intf_data[i].util_time + get_manual_utiltime(&csel->intf_data[i], csel->util_time_max))* csel->intf_sum, csel->util_time_max);	// round-up
	}
    
    // get normalized sum for 40M BW
	for (i=0;i<csel->chan_num;i++) {
		if (csel->intf_data[i].flag40) {
			if (csel->is_5g) {
				csel->intf_data[i].sum40 = 0;
				for (j=0;j<2;j++) {
					csel->intf_data[i].sum40 += csel->intf_data[i+j].sum20;
				}
			} else {
				csel->intf_data[i].sum40 = 
					  (csel->intf_data[i].val + csel->intf_data[i+4].val) 
					+ ((csel->intf_data[i].util_time + csel->intf_data[i+4].util_time) * csel->intf_sum40)/(csel->util_time_max*2)
					+ ROUNDUP((csel->intf_data[i].util_time + csel->intf_data[i+4].util_time) * csel->intf_sum40, csel->util_time_max*2);
			}
		}
	}
#endif

    // Modified expression for getting channel selection score.
    // Mutliply 5 at each index to get meaningful score.
	// get normalized sum for 20M BW
    for (i=0;i<csel->chan_num;i++) {
		csel->intf_data[i].sum20_org = 
			  (csel->intf_data[i].val * 5)
            + ((csel->intf_data[i].util_time * csel->intf_sum) / (csel->util_time_max / 5));
		csel->intf_data[i].sum20 = 
			  (csel->intf_data[i].val * 5)
            + (((csel->intf_data[i].util_time + get_manual_utiltime(&csel->intf_data[i], csel->util_time_max)) * csel->intf_sum) / (csel->util_time_max / 5));
	}

	// get normalized sum for 40M BW
	for (i=0;i<csel->chan_num;i++) {
		if (csel->intf_data[i].flag40) {
			if (csel->is_5g) {
				csel->intf_data[i].sum40 = 0;
				for (j=0;j<2;j++) {
					csel->intf_data[i].sum40 += csel->intf_data[i+j].sum20;
				}
			} else {
				csel->intf_data[i].sum40 = 
					  ((csel->intf_data[i].val + csel->intf_data[i+4].val) * 5) 
					+ ((csel->intf_data[i].util_time + csel->intf_data[i+4].util_time) * csel->intf_sum40) / (csel->util_time_max*2 / 5);
			}
		}
	}

	// get normalized sum for 80M BW
	for (i=0;i<csel->chan_num;i++) {
		if (csel->intf_data[i].flag80) {
			if (csel->is_5g) {
				csel->intf_data[i].sum80 = 0;
				for (j=0;j<4;j++) {
					csel->intf_data[i].sum80 += csel->intf_data[i+j].sum20_org;
				}
			} else {
				// no 80MHz for 2g
			}
		}
	}

	// select minimum
	min20 = min40 = min80 = MAX_INT32;
	i40 = i80 = -1;

	for (i=0;i<csel->chan_num;i++) {
		if (chan_selectable(csel->intf_data[i].chan, 1, csel->block_5g_bc_band) && csel->intf_data[i].sum20 <= min20) {
            if (!csel->is_5g || (csel->intf_data[i].sum20 < min20)) {
                min20_ctrl = csel->intf_data[i].chan;
                min20 = csel->intf_data[i].sum20;
            }
		}

        if (csel->intf_data[i].flag40) {
            if (chan_selectable(csel->intf_data[i].chan, 2, csel->block_5g_bc_band) && csel->intf_data[i].sum40 <= min40) {
                if (!csel->is_5g || (csel->intf_data[i].sum40 < min40)) {
                    min40 = csel->intf_data[i].sum40;
                    i40 = i;
                }
            }
        }

        if (csel->intf_data[i].flag80) {
            if (chan_selectable(csel->intf_data[i].chan, 4, csel->block_5g_bc_band) && csel->intf_data[i].sum80 < min80) {
                min80 = csel->intf_data[i].sum80;
                i80 = i;
            }
        }
	}

	// select control channel
	res->ctrl20 = min20_ctrl;

	if (i40 >= 0) {
		if (csel->is_5g) {
			min40=MAX_INT32;
			for (i=0;i<2;i++) {
				if (csel->intf_data[i40+i].sum20 < min40) {
					min40_ctrl = csel->intf_data[i40+i].chan;
                    min40 = csel->intf_data[i40+i].sum20;
				}
			}
		} else {
			if (csel->intf_data[i40].sum20 <= csel->intf_data[i40+4].sum20) {
				min40_ctrl = csel->intf_data[i40].chan;
			} else {
				min40_ctrl = csel->intf_data[i40+4].chan;
			}
		}
        
		res->ctrl40 = min40_ctrl;
		res->chan_sel40[0] = csel->intf_data[i40].chan;
		res->chan_sel40[1] = csel->intf_data[i40].chan + 4;
	}

	if (i80 >= 0) {
		min80=MAX_INT32;

		for (i=0;i<4;i++) {
			if (csel->intf_data[i80+i].sum20 < min80) {
				min80_ctrl = csel->intf_data[i80+i].chan;
				min80 = csel->intf_data[i80+i].sum20;
			}
		}
        
		res->ctrl80 = min80_ctrl;
		res->chan_sel80[0] = csel->intf_data[i80+0].chan;
		res->chan_sel80[1] = csel->intf_data[i80+1].chan;
		res->chan_sel80[2] = csel->intf_data[i80+2].chan;
		res->chan_sel80[3] = csel->intf_data[i80+3].chan;
	}
}

static void dump_chan_sel(struct chan_sel_t *csel, struct csel_result_t *res, char *buf, int szbuf)
{
	int i;
	int len=0;
	int ret;

	for (i=0;i<csel->chan_num;i++) {
		ret = snprintf(buf+len, szbuf-len, "ch:%d,intf:%d,util:%d,s20:%d,s40:%d,s80:%d,flag(%s:%s)\n", 
			csel->intf_data[i].chan, 
			csel->intf_data[i].val, 
			csel->intf_data[i].util_time, 
			csel->intf_data[i].sum20, 
			csel->intf_data[i].sum40, 
			csel->intf_data[i].sum80, 
			csel->intf_data[i].flag40?"4":".", 
			csel->intf_data[i].flag80?"8":".");
		if ((ret <= 0) || (ret >= (szbuf-len)))	len = szbuf;
		else 									len += ret;
	}
	ret = snprintf(buf+len, szbuf-len, "intf_sum:%d,intf_sum40:%d,util_max:%d\n", csel->intf_sum, csel->intf_sum40, csel->util_time_max);
	if ((ret <= 0) || (ret >= (szbuf-len)))	len = szbuf;
	else 									len += ret;

	ret = snprintf(buf+len, szbuf-len, "res20:%d,res40:%d(%d/%d),res80:%d(%d/%d/%d/%d),olap40:crit%d/maj%d\n",
			res->ctrl20, 	
			res->ctrl40, res->chan_sel40[0], res->chan_sel40[1],
			res->ctrl80, res->chan_sel80[0], res->chan_sel80[1], res->chan_sel80[2], res->chan_sel80[3],
			res->olap40crit, res->olap40maj);
	if ((ret <= 0) || (ret >= (szbuf-len)))	len = szbuf;
	else 									len += ret;
}

static struct chan_sel_t csel_2g, csel_5g;
static struct csel_result_t res_2g, res_5g;
#define CSEL_DATA(is_5g) (is_5g ? &csel_5g:&csel_2g)
#define CSEL_RES(is_5g) (is_5g ? &res_5g:&res_2g)

void csel_init(int is_5g, int block_5g_bc_band)
{
	chan_sel_init(CSEL_DATA(is_5g), is_5g, block_5g_bc_band);
}

void csel_update_ap_rssi(int is_5g, unsigned int *chan, int num_chan, int rssi)
{
	/*
	printk("%s():%d %s %d %d %d %d %d %d\n", __FUNCTION__, __LINE__, is_5g?"5":"2", 
		chan[0], chan[1], chan[2], chan[3], num_chan, rssi);
	*/
	chan_sel_intf_calc(CSEL_DATA(is_5g), chan, num_chan, rssi);
}

void csel_update_chan_util_time(int is_5g, unsigned int *chan, int num_chan, int util_time)
{
	chan_sel_util_calc(CSEL_DATA(is_5g), chan, num_chan, util_time);
}

void csel_result(int is_5g, struct csel_result_t *res)
{
	chan_sel_select(CSEL_DATA(is_5g), res);
	memcpy(CSEL_RES(is_5g), res, sizeof(struct csel_result_t));	// store selection result for dumping.
}

void csel_dump(int is_5g, char *buf, int szbuf)
{
	dump_chan_sel(CSEL_DATA(is_5g), CSEL_RES(is_5g), buf, szbuf);
}

void csel_store_overlapped_ap_cnt(int is_5g, int cnt_crit, int cnt_maj)
{
	CSEL_RES(is_5g)->olap40crit = cnt_crit;
	CSEL_RES(is_5g)->olap40maj = cnt_maj;
}

static void dump_to_log_chan_score(struct chan_sel_t *csel)
{
	int i, n, len;
	char buf[128];

	for (i = n = 0; i < csel->chan_num;) {
		len = snprintf(&buf[n], sizeof(buf) - n, "%c%d(%d,%d,%d)",
			       (n > 0) ? ' ' : '+',
			       csel->intf_data[i].chan, csel->intf_data[i].sum20,
			       csel->intf_data[i].sum40, csel->intf_data[i].sum80);
		if (len >= (sizeof(buf) - n)) {
			if (n == 0)
				printk("%s\n", buf);
			else {
				printk("%.*s\n", n, buf);
				n = 0;
				continue;
			}
		} else if (((i + 1) % 5) == 0) {
			printk("%s\n", buf);
			n = 0;
		} else
			n += len;
		i++;
	}
	if (n > 0)
		printk("%s\n", buf);
}

void csel_dump_to_log(int is_5g)
{
	dump_to_log_chan_score(CSEL_DATA(is_5g));
}
