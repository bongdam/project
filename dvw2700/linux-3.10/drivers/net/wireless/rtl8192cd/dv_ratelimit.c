#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include "dv_ratelimit.h"

#define TIME_DIFF(n, b)	((__u32)(n) >= (__u32)(b)) ? \
		((__u32)(n) - (__u32)(b)) : (((__u32)-1) - (__u32)(b) + 1 + ((__u32)(n)))

static int BURST_WIN = 1000 * HZ / 1000;

int get_BURST_WIN(void)
{
	return (BURST_WIN * 1000 / HZ);
}

void set_BURST_WIN(int val)
{
	BURST_WIN = val * HZ / 1000;
}

static inline long dv_ratelimit_hist_delta(unsigned long last, unsigned long last_bytes,
		unsigned long intv, unsigned long refill, unsigned long *remains)
{
	int diff, quotient, remainder;
	int maxbytes, curbytes;

	diff = TIME_DIFF(jiffies, last);
	if (diff < (BURST_WIN - intv)) {
		quotient = diff / intv;
		remainder = diff % intv;
		curbytes = last_bytes + refill * quotient;
		maxbytes = (BURST_WIN - intv) * refill / intv;
		*remains = intv - remainder;

		return (curbytes > maxbytes) ? maxbytes : curbytes;
	} else {
		*remains = intv;

		return refill;
	}
}

int dv_ratelimit_verdict(dv_ratelimit_ctrl_t *p, int bytes)
{
	unsigned long remains;
	long tmp;
	if(!p)
		return DV_RATELIMIT_PASS;

	if (time_after_eq(jiffies, p->due_jiffies)) {
		tmp = dv_ratelimit_hist_delta(p->due_jiffies, p->last_bytes,
				p->intvl_jiffies, p->quota_bytes, &remains);
		p->last_bytes = (long)p->quota_bytes + tmp;
		if (p->peak_bytes && p->last_bytes > p->peak_bytes)
			p->last_bytes = p->peak_bytes;
		p->due_jiffies = jiffies + remains;
	}

	if (p->last_bytes >= bytes) {
		p->last_bytes -= bytes;
		return DV_RATELIMIT_PASS; // PASS
	}

	return DV_RATELIMIT_DROP; // DROP
}

void dv_ratelimit_set_ctrl(dv_ratelimit_ctrl_t *p, unsigned long quota, unsigned long peak_bytes, int intv)
{
	uint64_t tmp;
	memset(p, 0, sizeof(dv_ratelimit_ctrl_t));
	if ((quota == 0) && (intv == 0))
		return;

	p->intvl_jiffies = (intv*HZ)/1000;
	p->due_jiffies = jiffies + p->intvl_jiffies;

	p->quota_bytes = quota;
	tmp = (uint64_t)p->quota_bytes * p->intvl_jiffies;
	do_div(tmp, HZ);
	p->quota_bytes = (unsigned long)tmp;
	p->last_bytes = p->quota_bytes;
	p->peak_bytes = peak_bytes;
}

static ulong convert_bps(ulong bytes, ulong intvl)
{
	if (intvl==0)
		intvl = 1;
	return (bytes << 3) / intvl * HZ ;
}

char *rate_limit_show(dv_ratelimit_ctrl_t *p, char *buf, int buf_len)
{
	int len = 0;
	len += snprintf(&buf[len], buf_len-len, "%10lu %10lu %5lu %10lu ",
			convert_bps(p->quota_bytes, p->intvl_jiffies),
			convert_bps(p->last_bytes, p->intvl_jiffies),
			p->intvl_jiffies * 1000 / HZ,
			p->peak_bytes);
	return buf;
}

