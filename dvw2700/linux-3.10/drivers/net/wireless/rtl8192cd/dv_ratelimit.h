#ifndef __DV_RATELIMIT_H__
#define __DV_RATELIMIT_H__

#define DV_RATELIMIT_INTV 50

#define DV_RATELIMIT_DROP 0
#define DV_RATELIMIT_PASS 1

typedef struct {
	unsigned long last_bytes;
	unsigned long due_jiffies;
	unsigned long quota_bytes;
	unsigned long intvl_jiffies;
	unsigned long peak_bytes;
} dv_ratelimit_ctrl_t;

int dv_ratelimit_verdict(dv_ratelimit_ctrl_t *limit_ctrl, int bytes);
void dv_ratelimit_set_ctrl(dv_ratelimit_ctrl_t *p, unsigned long quota, unsigned long peak_bytes, int intv);
char *rate_limit_show(dv_ratelimit_ctrl_t *p, char *buf, int buf_len);
void set_BURST_WIN(int val);
int get_BURST_WIN(void);

#endif

