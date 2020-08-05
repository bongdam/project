#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <syslog.h>
#include <dvflag.h>
#include <libytool.h>
#include <shutils.h>
#include <brdio.h>
#include <shutils.h>
#include <include/linux/dvqos_ioctl.h>
#include <bcmnvram.h>
#include "instrument.h"
#include "cmd.h"
#include <sys/sysinfo.h>

enum {
	DECONFIG = 0,
	BOUND = 1,
};

enum {
	WAN_IP_ASSIGNED = 1,
	WAN_IP_CHANGED = 2,
};

extern long trap_timer_id;
extern long sched_trap_timer(unsigned int sec);
extern int virtual_ssid_enable(int on);

static int wan_bound = -1;
static long wan_act_tid;
static int snmp_chan_bonding;

static unsigned int set_WFQ_Rate(int port);
static int get_wan_ip(in_addr_t *ip);
static void slow_wan_action(int arg);

static void holepunch_event(void);
static void child_guard_event(void);

static void send_link_trap(int up, int bpos);

#define wan_up() slow_wan_action(BOUND)
#define wan_down() slow_wan_action(DECONFIG)

struct link_status {
	const unsigned int bpos;
	const char *name;
	unsigned int tstamp;	/* centisecond */
};

static struct link_status status[] = {
	{
	 .bpos = DF_WANLINK,
	 .name = "WAN",
	 },
	{
	 .bpos = DF_LANLINK1,
	 .name = "LAN1",
	 },
	{
	 .bpos = DF_LANLINK2,
	 .name = "LAN2",
	 },
	{
	 .bpos = DF_LANLINK3,
	 .name = "LAN3",
	 },
	{
	 .bpos = DF_LANLINK4,
	 .name = "LAN4",
	 },
	{
	 .bpos = DF_WANBOUND,
	 .name = "WANBOUND",
	 },
};

static unsigned int linkmask;
static unsigned int flg, oldflg;
static unsigned int stk[2];
static int stk_ptr;

static unsigned int centisecond(void)
{
	struct timespec ts;
	ygettime(&ts);
	return (ts.tv_sec * 100) + (ts.tv_nsec / 10000000);
}

int link_watcher_init(void)
{
	unsigned int i;
	int fd;

	fd = open("/proc/dvflag", O_RDWR);
	if (fd < 0)
		return -1;

	for (i = linkmask = 0; i < _countof(status); i++)
		linkmask |= status[i].bpos;

	ioctl(fd, DVFLGIO_SETMASK, &linkmask);
	read(fd, (void *)&flg, sizeof(flg));
	flg &= linkmask;
	oldflg = flg;

	return fd;
}

int link_watcher_read(int fd)
{
	struct link_status *p;
	unsigned int changed, csec;
	int i, up, inited, speed;
	unsigned int phystat;
	struct sysinfo info;

	if (read(fd, (void *)&flg, sizeof(flg)) <= 0)
		return -1;

	if (wan_bound < 0) {
		if ((flg & (DF_WANLINK|DF_WANBOUND)) == (DF_WANLINK|DF_WANBOUND))
			wan_up();
		else
			wan_down();
	}

	inited = !!(flg & DF_INITED);
	flg &= linkmask;
	changed = oldflg ^ flg;
	if (changed) {
		csec = centisecond();
		for (i = 0; i < _countof(status); i++) {
			p = &status[i];
			if (changed & p->bpos) {
				up = !!(flg & p->bpos);
				if (inited && p->bpos != DF_WANBOUND) {
					/* jihyun@davo150606 jcode#0 */
					phystat = set_WFQ_Rate(p->bpos);
					if (up) {
						if (phystat & PHF_10M)
							speed = 10;
						else if (phystat & PHF_100M)
							speed = 100;
						else if (phystat & PHF_500M)
							speed = 500;
						else
							speed = 1000;
						syslog(LOG_INFO, "%s Link %dMb/s %s 연결됨", p->name,
						       speed, (phystat & PHF_FDX) ? "Full" : "Half");
					} else
						syslog(LOG_INFO, "%s Link 연결 끊어짐", p->name);
					send_link_trap(up, p->bpos);
				}

				if (p->bpos == DF_WANLINK) {
					if (up) {
						if (flg & DF_WANBOUND)
							wan_up();
					} else
						wan_down();
				} else if (p->bpos == DF_WANBOUND) {
					if (up)
						wan_up();
					else
						wan_down();
				}
				p->tstamp = csec;
			}
		}
/*
 * ----------+----------+----------+----------+----------+----------+----------
 *  time seq |bound/link|bound/link|bound/link|bound/link|bound/link|bound/link
 * ----------+----------+----------+----------+----------+----------+----------
 * 2nd behind|  F*   F     F*   F     T*   F     F*   T     T*   T     T*   T
 *  behind   |  T*   F     F*   T     F*   T     F*   F     T*   F     F*   T
 *   now     |  T    T     T    T     T    T     T    T     T    T     T    T
 * ----------+----------+----------+----------+----------+----------+----------
 *           |xmit-trap |xmit-trap |xmit-trap |xmit-trap |   ---    |xmit-trap
 * ----------+----------+----------+----------+----------+----------+----------
 * There is precondition that event mask should be stacked onto only when any
 * event bit is inverted. The general rule could be coined with reference to
 * the table above.
 * The result of AND operation of the bound bit of '2nd behind' and 'behind'
 * was always FALSE in case of being able to transmit trap.
 */
		if (test_any_bit(DF_WANLINK|DF_WANBOUND, changed)) {
			if (trap_timer_id && test_all_bits(DF_WANLINK|DF_WANBOUND, flg)) {
				if (!test_any_bit(DF_WANBOUND, stk[0] & stk[1])) {
					sysinfo(&info);
					itimer_cancel(trap_timer_id, NULL);
					trap_timer_id = sched_trap_timer((info.uptime >= 150)? 1 : (150 - info.uptime));
				}
			}
			stk[stk_ptr] = flg & (DF_WANLINK|DF_WANBOUND);
			stk_ptr ^= 1;
		}
	}
	oldflg = flg;
	return 0;
}

static int mod_link_watcher(int argc, char **argv, char *response_pipe)
{
	int fd = open_reply_pipe(response_pipe);
	struct link_status *p;
	char *name;
	int i, n = 0;

	name = (argc > 1) ? argv[1] : NULL;
	for (i = 0; i < _countof(status); i++) {
		p = &status[i];
		if (name == NULL || !strcmp(name, p->name)) {
			if (fd > -1)
				n += dprintf(fd, "%u %s %s\n", p->tstamp, p->name,
					     (flg & p->bpos) ? "UP" : "DOWN");
			if (name)
				break;
		}
	}

	if (fd > -1) {
		if (n == 0)
			dprintf(fd, "\n");
		close(fd);
	}
	return 0;
}

static void __attribute__ ((constructor)) register_link_watcher_module(void)
{
	fifo_cmd_register("link_watcher", "\t[WAN|LAN1|LAN2|LAN3|LAN4]",
			  "Show link status", mod_link_watcher);
}

/* jihyun@davo150606 jcode#0 */
// Change Total Bandwidth of Weighted fair queue
#define QOS_FILE_NAME "/dev/dvqos"
#define QOS_WFQRCRP0  0x1b0

void write_qos_reg(int off, unsigned int val)
{
	int fd;
	struct qos_reg_t data;
	fd = open(QOS_FILE_NAME, O_RDWR);
	if (fd < 0) {
		return;
	}
	data.reg = off;
	data.val = val;

	ioctl(fd, DVQOS_OP_WRITEREG, (void *)&data);
	close(fd);
}

static unsigned int set_WFQ_Rate(int port)
{
	int reg;
	unsigned int val;
	char buf[32];
	int rate_16k;
	unsigned int phy_status;
	int phy_port = -1;

	if (port == DF_WANLINK)
		phy_port = 4;
	else if (port == DF_LANLINK1)
		phy_port = 0;
	else if (port == DF_LANLINK2)
		phy_port = 1;
	else if (port == DF_LANLINK3)
		phy_port = 2;
	else if (port == DF_LANLINK4)
		phy_port = 3;

	if ((phy_port < 0) || (phy_port >= 7))
		return 0;

	sprintf(buf, "x_QOS_RATE_ENABLE_%d", phy_port);
	if (nvram_get_int(buf, 0)) {	// 0 = disable, 1=enable
		sprintf(buf, "x_QOS_RATE_O_%d", phy_port);
		rate_16k = nvram_get_int(buf, 0) / 16;
	} else
		rate_16k = 0;

	phy_status = switch_port_status(phy_port);
	if (rate_16k != 0)
		return phy_status;

	if (phy_status & PHF_LINKUP) {
		reg = QOS_WFQRCRP0 + 12 * phy_port;
		if (phy_status & PHF_10M) {	// 10M
			val = 0x00a0;	// 0xa0 * 64K = 10240
		} else if (phy_status & PHF_100M) {	// 100M
			val = 0x0640;	// 0x640 * 64K = 102400
		} else if (phy_status & PHF_500M) {	// 500M
			val = 0x1f40;	//0x1f40 * 64K = 512000
		} else {	// 1000M
			val = 0x3fff;	// disable out rate control
		}
		write_qos_reg(reg, val);
	}

	return phy_status;
}

#if 0
static void ip_assigned_action(void)
{
}
#endif

static void ip_changed_action(void)
{
	/* auth : reconnect radius server */
	yecho("/var/tmp/disc_sta", "svr_reconnect");
	killall(SIGUSR2, "auth");
}

static void cpeping_wanCheck(void)
{
	int pid = 0;
	yfcat("/var/run/snmp_cpeping.pid", "%d", &pid);
	if (pid > 1)
		kill(pid, SIGUSR1);
}

static void ip_changed_check(void)
{
	static in_addr_t cur_wan_ip = 0;
	in_addr_t wan_ip = 0;

	if (get_wan_ip(&wan_ip) == 0)
		return;

	if (!cur_wan_ip && wan_ip) {
//              ip_assigned_action();
	} else if (cur_wan_ip != wan_ip) {
		ip_changed_action();
		cpeping_wanCheck();
	}
	cur_wan_ip = wan_ip;
}

static int wan_action(int bound)
{
	if (bound == BOUND)
		ip_changed_check();

	if (wan_bound == bound)
		return 0;

	if (bound == BOUND)
		virtual_ssid_enable(1);
	else if (bound == DECONFIG)
		virtual_ssid_enable(0);

	wan_bound = bound;
	return 0;
}

static int get_wan_ip(in_addr_t *ip)
{
	char buf[32];

	if (yfcat("/var/wan_ip", "%31s", buf) > 0 &&
	    inet_pton(AF_INET, buf, ip) == 1) {
		if (ip[0] && ip[0] != INADDR_NONE)
			return 1;
	}
	return 0;
}

static int slow_wan_action_callback(long id, unsigned long arg)
{
	(void)id;

	wan_action((int)arg);
	wan_act_tid = 0;
	return 0;
}

static void slow_wan_action(int arg)
{
	struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
	itimer_cancel(wan_act_tid, NULL);
	wan_act_tid = itimer_creat(arg, slow_wan_action_callback, &tv);
	if(arg == BOUND) {
		holepunch_event();
		child_guard_event();
		yexecl(NULL, "sh -c \"snmp -m 5 13 &\"");
		//trap#8: auto bandwidth trap
		if ( (!snmp_chan_bonding ||
			(nvram_match("WAN_DHCP", "0")&& snmp_chan_bonding ==1)) &&
			nvram_match("WLAN1_CHANNEL", "0") && nvram_match("WLAN1_WLAN_DISABLED", "0") &&
			nvram_match("x_wlan1_auto_bonding", "1") ) {
			snmp_chan_bonding++;
			yexecl(NULL, "sh -c \"snmp -m 8 &\"");
		}
	}
}

static void holepunch_event(void)
{
	int pid = 0;
	yfcat("/var/run/holepunch.pid", "%d", &pid);

	if(pid > 0)
		killall(SIGKILL, "holepunch");

	if (nvram_get_int("x_holepunch_enabled", 1) == 1)
		yexecl(NULL, "sh -c \"holepunch &\"");
}

static void child_guard_event(void)
{
	int pid = 0;
	int op_mode = 0;

	yfcat("/var/sys_op", "%d", &op_mode);

	if (op_mode != 0)
		return;

	yfcat("/var/run/child_guard.pid", "%d", &pid);

	if(pid > 0) {
		killall(SIGKILL, "child_guard");
		usleep(50000);
	}

	yexecl(NULL, "sh -c \"child_guard &\"");
}

static void send_link_trap(int up, int bpos)
{
	int i;
	int trap_flag = 0;
	char trap_cmd[80];

	trap_cmd[0]=0;
	trap_flag = (up)?8:0;
	for ( i = 1; i < 5; i++) {
		if ( bpos &(1<<i) ) {
			trap_flag |= i;
			sprintf(&trap_cmd[0], "sh -c \"snmp -m 5 %d &\"", trap_flag);
			yexecl(NULL, trap_cmd);
			break;
		}
	}
}
