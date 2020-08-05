#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <sys/utsname.h>
#include <brdio.h>
#include <libytool.h>
#include <shutils.h>
#include "instrument.h"
#include "cmd.h"

extern void read_uptime(u_int64_t *uptime);
extern u_int64_t get_interval(u_int64_t prev_uptime,
				u_int64_t curr_uptime);
extern char *strtime(const time_t *timep, char *buf);
extern double ll_sp_value(unsigned long long value1, unsigned long long value2,
		   unsigned long long itv);

static struct stats_ether rx_stats_per_port[2][5];
static u_int64_t uptime[2] = { 0, 0 };
static time_t tstamp[2];
static const char rate_suffix[] = "\0\0k\0m\0g\0t";

static int curr = 1;
static int verbose = 0;
static long timer_id;

static void read_stat_ether(struct stats_ether _st_eth[5])
{
	int fd;

	fd = open("/proc/brdio", O_RDWR);
	if (fd != -1) {
		ioctl(fd, BIOCGETHRX, _st_eth);
		close(fd);
	}
}

static int do_scaled_octet(struct scaled_octet *p)
{
	return dec_scaled_octet(p);
}

void print_eth_stats(int prev, int curr)
{
	struct stats_ether *scp = rx_stats_per_port[prev], *scc = rx_stats_per_port[curr];
	u_int64_t g_itv;
	struct scaled_octet bps;
	char buf[16];
	int i, n;

	/* compute time interval */
	g_itv = get_interval(uptime[prev], uptime[curr]);
	for (i = 0; i < _countof(rx_stats_per_port[0]); i++, scp++, scc++) {
		if (i == 0)
			printf("%s  ", strtime(&tstamp[curr], buf));
		bps.ull = (u_int64_t)ll_sp_value(scp->rx_bytes, scc->rx_bytes, g_itv);
		bps.ull <<= 3;
		n = do_scaled_octet(&bps);
		printf("p%d %lu.%u%sb%s", i, (unsigned long)bps.N, bps.F / 100, &rate_suffix[n << 1],
			i < (_countof(rx_stats_per_port[0]) - 1) ? "  " : "\n");
	}
}

static int eth_stat_worker(long id, unsigned long arg)
{
	time(&tstamp[curr]);
	read_uptime(&uptime[curr]);
	read_stat_ether(rx_stats_per_port[curr]);
	if (verbose)
		print_eth_stats(!curr, curr);
	curr ^= 1;
	return 1;
}

static long eth_stat(time_t interval)
{
	struct timeval tv = {.tv_sec = interval,.tv_usec = 0 };

	memset(uptime, 0, sizeof(uptime));
	memset(tstamp, 0, sizeof(tstamp));
	curr = 1;
	time(&tstamp[0]);
	read_uptime(&uptime[0]);
	read_stat_ether(rx_stats_per_port[0]);
	return itimer_creat(0UL, eth_stat_worker, &tv);
}

static int mod_eth_stat(int argc, char **argv, char *response_pipe)
{
	int fd = open_reply_pipe(response_pipe);
	int i, len = 0;

	if (fd < 0)
		return -1;
	if (argc > 2) {
		if (!strcmp("interval", argv[1])) {
			i = strtol(argv[2], NULL, 0);
			if (i > 0) {
				if (timer_id)
					itimer_cancel(timer_id, NULL);
				timer_id = eth_stat(i);
			} else if (timer_id) {
				itimer_cancel(timer_id, NULL);;
				timer_id = 0;
			}
			len = dprintf(fd, "\n");
		} else if (!strcmp("verbose", argv[1])) {
			verbose = !!strtol(argv[2], NULL, 0);
			len = dprintf(fd, "\n");
		}
	}
	if (len == 0)
		print_eth_stats(curr, !curr);
	close(fd);
	return 0;
}

static void __attribute__ ((constructor)) register_eth_stat_module(void)
{
	fifo_cmd_register("eth_stat", "\t[verbose <1|0>]\n\t[interval <secs>]",
			"show ethernet statistic", mod_eth_stat);
	timer_id = eth_stat(2);
}
