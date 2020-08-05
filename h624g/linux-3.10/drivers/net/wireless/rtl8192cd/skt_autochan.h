#ifndef __SKT_AUTOCHAN_H__
#define __SKT_AUTOCHAN_H__

#define MAX_BONDING_CHAN 4

struct csel_result_t {
	unsigned int ctrl20;
	unsigned int ctrl40;
	unsigned int ctrl80;
	unsigned int chan_sel40[2];
	unsigned int chan_sel80[4];
	unsigned int olap40crit;
	unsigned int olap40maj;
};

#define CSEL_2G 0
#define CSEL_5G 1

typedef int (*print_t)(char *fmt, ...);

extern void csel_init(int is_5g, int block_5g_bc_band);
extern void csel_update_ap_rssi(int is_5g, unsigned int *chan, int num_chan, int rssi);
extern void csel_update_chan_util_time(int is_5g, unsigned int *chan, int num_chan, int util_time);
extern void csel_result(int is_5g, struct csel_result_t *res);
extern void csel_dump(int is_5g, char *buf, int szbuf);
extern void csel_store_overlapped_ap_cnt(int is_5g, int cnt_crit, int cnt_maj);
extern void csel_dump_to_log(int is_5g);

#endif

