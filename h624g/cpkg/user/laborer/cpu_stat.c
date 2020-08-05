#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <ctype.h>
#include <sys/utsname.h>
#include "instrument.h"
#include "cmd.h"

struct stats_cpu {
	unsigned long long cpu_user	__attribute__ ((aligned(16)));
	unsigned long long cpu_nice	__attribute__ ((aligned(16)));
	unsigned long long cpu_sys	__attribute__ ((aligned(16)));
	unsigned long long cpu_idle	__attribute__ ((aligned(16)));
	unsigned long long cpu_iowait	__attribute__ ((aligned(16)));
	unsigned long long cpu_steal	__attribute__ ((aligned(16)));
	unsigned long long cpu_hardirq	__attribute__ ((aligned(16)));
	unsigned long long cpu_softirq	__attribute__ ((aligned(16)));
	unsigned long long cpu_guest	__attribute__ ((aligned(16)));
};

#define STATS_CPU_SIZE	(sizeof(struct stats_cpu))

static unsigned long long uptime[3] = { 0, 0, 0 };
static unsigned long long uptime0[3] = { 0, 0, 0 };
static time_t tstamp[3];

static struct stats_cpu *st_cpu[3];
static int cpu_nr = 0;
static int curr = 1;
static int dis = 1;
static int verbose = 0;
static long timer_id;

void read_uptime(unsigned long long *uptime)
{
	FILE *fp;
	char line[128];
	unsigned long up_sec, up_cent, HZ = sysconf(_SC_CLK_TCK);

	if ((fp = fopen("/proc/uptime", "r")) == NULL)
		return;

	if (fgets(line, 128, fp) == NULL) {
		fclose(fp);
		return;
	}

	sscanf(line, "%lu.%lu", &up_sec, &up_cent);
	*uptime = (unsigned long long)up_sec *HZ +
	    (unsigned long long)up_cent *HZ / 100;

	fclose(fp);
}

static int get_proc_cpu_nr(void)
{
	FILE *fp;
	char line[16];
	int num_proc, proc_nr = -1;

	if ((fp = fopen("/proc/stat", "r")) == NULL) {
		fprintf(stderr, "Cannot open %s: %s\n", "/proc/stat",
			strerror(errno));
		exit(1);
	}

	while (fgets(line, 16, fp) != NULL) {
		if (strncmp(line, "cpu ", 4) && !strncmp(line, "cpu", 3)) {
			sscanf(line + 3, "%d", &num_proc);
			if (num_proc > proc_nr) {
				proc_nr = num_proc;
			}
		}
	}

	fclose(fp);

	return (proc_nr + 1);
}

void read_stat_cpu(struct stats_cpu *_st_cpu, int nbr,
		   unsigned long long *uptime, unsigned long long *uptime0)
{
	FILE *fp;
	struct stats_cpu *st_cpu_i;
	struct stats_cpu sc;
	char line[8192];
	int proc_nb;

	if ((fp = fopen("/proc/stat", "r")) == NULL) {
		fprintf(stderr, "Cannot open %s: %s\n", "/proc/stat",
			strerror(errno));
		exit(2);
	}

	while (fgets(line, 8192, fp) != NULL) {

		if (!strncmp(line, "cpu ", 4)) {

			/*
			 * All the fields don't necessarily exist,
			 * depending on the kernel version used.
			 */
			memset(_st_cpu, 0, STATS_CPU_SIZE);

			/*
			 * Read the number of jiffies spent in the different modes
			 * (user, nice, etc.) among all proc. CPU usage is not reduced
			 * to one processor to avoid rounding problems.
			 */
			sscanf(line + 5,
			       "%llu %llu %llu %llu %llu %llu %llu %llu %llu",
			       &_st_cpu->cpu_user, &_st_cpu->cpu_nice,
			       &_st_cpu->cpu_sys, &_st_cpu->cpu_idle,
			       &_st_cpu->cpu_iowait, &_st_cpu->cpu_hardirq,
			       &_st_cpu->cpu_softirq, &_st_cpu->cpu_steal,
			       &_st_cpu->cpu_guest);

			/*
			 * Compute the uptime of the system in jiffies (1/100ths of a second
			 * if HZ=100).
			 * Machine uptime is multiplied by the number of processors here.
			 *
			 * NB: Don't add cpu_guest because cpu_user already includes it.
			 */
			*uptime = _st_cpu->cpu_user + _st_cpu->cpu_nice +
			    _st_cpu->cpu_sys + _st_cpu->cpu_idle +
			    _st_cpu->cpu_iowait + _st_cpu->cpu_hardirq +
			    _st_cpu->cpu_steal + _st_cpu->cpu_softirq;
		}

		else if (!strncmp(line, "cpu", 3)) {
			if (nbr > 1) {
				/* All the fields don't necessarily exist */
				memset(&sc, 0, STATS_CPU_SIZE);
				/*
				 * Read the number of jiffies spent in the different modes
				 * (user, nice, etc) for current proc.
				 * This is done only on SMP machines.
				 */
				sscanf(line + 3,
				       "%d %llu %llu %llu %llu %llu %llu %llu %llu %llu",
				       &proc_nb, &sc.cpu_user, &sc.cpu_nice,
				       &sc.cpu_sys, &sc.cpu_idle,
				       &sc.cpu_iowait, &sc.cpu_hardirq,
				       &sc.cpu_softirq, &sc.cpu_steal,
				       &sc.cpu_guest);

				if (proc_nb < (nbr - 1)) {
					st_cpu_i = _st_cpu + proc_nb + 1;
					*st_cpu_i = sc;
				}
				/*
				 * else additional CPUs have been dynamically registered
				 * in /proc/stat.
				 */

				if (!proc_nb && !*uptime0) {
					/*
					 * Compute uptime reduced to one proc using proc#0.
					 * Done if /proc/uptime was unavailable.
					 *
					 * NB: Don't add cpu_guest because cpu_user already
					 * includes it.
					 */
					*uptime0 = sc.cpu_user + sc.cpu_nice +
					    sc.cpu_sys + sc.cpu_idle +
					    sc.cpu_iowait + sc.cpu_steal +
					    sc.cpu_hardirq + sc.cpu_softirq;
				}
			}
		}
	}

	fclose(fp);
}

#define SP_VALUE(m,n,p)	(((double) ((n) - (m))) / (p) * 100)

double ll_sp_value(unsigned long long value1, unsigned long long value2,
		   unsigned long long itv)
{
	if ((value2 < value1) && (value1 <= 0xffffffff))
		/* Counter's type was unsigned long and has overflown */
		return ((double)((value2 - value1) & 0xffffffff)) / itv * 100;
	else
		return SP_VALUE(value1, value2, itv);
}

unsigned long long get_interval(unsigned long long prev_uptime,
				unsigned long long curr_uptime)
{
	/* prev_time=0 when displaying stats since system startup */
	unsigned long long itv = curr_uptime - prev_uptime;
	if (!itv)	/* Paranoia checking */
		itv = 1;
	return itv;
}

char *strtime(const time_t *timep, char *buf)
{
	struct tm *tm = localtime(timep);
	sprintf(buf, "%02d:%02d:%02d", tm->tm_hour, tm->tm_min, tm->tm_sec);
	return buf;
}

void write_stats_core(int prev, int curr, int dis)
{
	struct stats_cpu *scp = st_cpu[prev], *scc = st_cpu[curr];
	unsigned long long g_itv;
	char buf[16];

	/* compute time interval */
	g_itv = get_interval(uptime[prev], uptime[curr]);
	/* print cpu stats */
	if (dis)
		printf("\n%-11s  CPU    %%usr   %%nice    %%sys %%iowait    %%irq   "
		       "%%soft  %%steal  %%guest   %%idle\n", strtime(&tstamp[prev], buf));

	printf("%-11s  all  %6.2f  %6.2f  %6.2f  %6.2f  %6.2f  %6.2f  %6.2f  %6.2f  %6.2f\n",
	       strtime(&tstamp[curr], buf),
	       (scc->cpu_user - scc->cpu_guest) < (scp->cpu_user - scp->cpu_guest) ?
		0.0 : ll_sp_value(scp->cpu_user - scp->cpu_guest,
				  scc->cpu_user - scc->cpu_guest, g_itv),
	       ll_sp_value(scp->cpu_nice, scc->cpu_nice, g_itv),
	       ll_sp_value(scp->cpu_sys, scc->cpu_sys, g_itv),
	       ll_sp_value(scp->cpu_iowait, scc->cpu_iowait, g_itv),
	       ll_sp_value(scp->cpu_hardirq, scc->cpu_hardirq, g_itv),
	       ll_sp_value(scp->cpu_softirq, scc->cpu_softirq, g_itv),
	       ll_sp_value(scp->cpu_steal, scc->cpu_steal, g_itv),
	       ll_sp_value(scp->cpu_guest, scc->cpu_guest, g_itv),
	       (scc->cpu_idle < scp->cpu_idle) ?
		0.0 : ll_sp_value(scp->cpu_idle, scc->cpu_idle, g_itv));
}

static int mp_stat(long id, unsigned long arg)
{
	struct stats_cpu *scc;
	int cpu;

	for (cpu = 1; cpu <= cpu_nr; cpu++) {
		scc = st_cpu[curr] + cpu;
		memset(scc, 0, STATS_CPU_SIZE);
	}
	time(&tstamp[curr]);
	if (cpu_nr > 1) {
		uptime0[curr] = 0;
		read_uptime(&(uptime0[curr]));
	}
	read_stat_cpu(st_cpu[curr], cpu_nr + 1, &(uptime[curr]),
		      &(uptime0[curr]));
	if (verbose) {
		write_stats_core(!curr, curr, dis);
		dis = 0;
	}
	curr ^= 1;
	return 1;
}

static long cpu_stat(time_t interval)
{
	struct timeval tv = {.tv_sec = interval,.tv_usec = 0 };
	int i;

	memset(uptime, 0, sizeof(uptime));
	memset(uptime0, 0, sizeof(uptime0));
	memset(tstamp, 0, sizeof(tstamp));
	curr = 1;

	cpu_nr = get_proc_cpu_nr();
	if (cpu_nr > 1) {
		/*
		 * Init uptime0. So if /proc/uptime cannot fill it,
		 * this will be done by /proc/stat.
		 */
		uptime0[0] = 0;
		read_uptime(&(uptime0[0]));
	}

	for (i = 0; i < 3; i++) {
		if (st_cpu[i])
			free(st_cpu[i]);
		st_cpu[i] = (struct stats_cpu *)calloc(STATS_CPU_SIZE * (cpu_nr + 1), 1);
	}

	time(&tstamp[0]);
	read_stat_cpu(st_cpu[0], cpu_nr + 1, &(uptime[0]), &(uptime0[0]));
	uptime[2] = uptime[0];
	uptime0[2] = uptime0[0];
	tstamp[2] = tstamp[0];
	memcpy(st_cpu[2], st_cpu[0], STATS_CPU_SIZE * (cpu_nr + 1));

	return itimer_creat(0UL, mp_stat, &tv);
}

static int mod_cpu_stat(int argc, char **argv, char *response_pipe)
{
	int fd = open_reply_pipe(response_pipe);
	int i, len = 0;
	unsigned long long g_itv;

	if (fd < 0)
		return -1;
	if (argc > 2) {
		if (!strcmp("interval", argv[1])) {
			i = strtol(argv[2], NULL, 0);
			if (i > 0) {
				if (timer_id)
					itimer_cancel(timer_id, NULL);
				timer_id = cpu_stat(i);
			} else if (timer_id) {
				itimer_cancel(timer_id, NULL);;
				timer_id = 0;
			}
			len = dprintf(fd, "\n");
		} else if (!strcmp("verbose", argv[1])) {
			i = !!strtol(argv[2], NULL, 0);
			if (verbose != i)
				dis = 1;
			verbose = i;
			len = dprintf(fd, "\n");
		}
	}
	if (len == 0) {
		g_itv = get_interval(uptime[curr], uptime[!curr]);
		dprintf(fd, "%6.2f\n", (st_cpu[!curr]->cpu_idle < st_cpu[curr]->cpu_idle) ? 0.0 :
			ll_sp_value(st_cpu[curr]->cpu_idle, st_cpu[!curr]->cpu_idle, g_itv));
	}
	close(fd);
	return 0;
}

static void __attribute__ ((constructor)) register_cpu_stat_module(void)
{
	fifo_cmd_register("cpu_stat", "\t[verbose <1|0>]\n\t[interval <secs>]",
			"control cpu_stat module", mod_cpu_stat);
	timer_id = cpu_stat(5);
}
