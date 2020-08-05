#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <libytool.h>
#include <dvflag.h>
#include <bcmnvram.h>
#include <syslog.h>
#include <signal.h>

#include "linux_list.h"
#include "child_guard.h"

int cnt = 0;
member_t member[CHILD_MAX];

static void check_ntp(void)
{
	int fd, flag;
	static int log_stamp = -1;

	while (1) {
		fd = open("/proc/dvflag", O_RDONLY);
		if (fd >= 0) {
			if (read(fd, (void *)&flag, sizeof(flag)) > 0) {
				if (flag & DF_NTPSYNC) {
					close(fd);
					break;
				} else {
					if (log_stamp < 0) {
						syslog(LOG_INFO, "[Child_Guard] NTP Sync Fail!! Stop Service.");
						log_stamp = 0;
					}
				}
			}
			close(fd);
		}
		sleep(1);
	}
}

static void make_iptables_chain(void)
{
	char lan_ip[32] = {0,};
	char value[12] = {0,};
	int redirect_port;

	nvram_get_r_def("IP_ADDR", lan_ip, sizeof(lan_ip), "192.168.35.1");
	nvram_get_r_def("x_redirect_port", value, sizeof(value), "876");
	redirect_port = strtoul(value, NULL, 10);

	yexecl(NULL, "iptables -N MACFILTER -t nat");
	yexecl(NULL, "iptables -N MACFILTER_DROP -t nat");

	yexecl(NULL, "iptables -F MACFILTER -t nat");
	yexecl(NULL, "iptables -F MACFILTER_DROP -t nat");

	yexecl(NULL, "iptables -A MACFILTER_DROP -t nat -p icmp -j RETURN");
	yexecl(NULL, "iptables -A MACFILTER_DROP -t nat -p udp --dport 53 -j RETURN");
	yexecl(NULL, "iptables -A MACFILTER_DROP -t nat -p udp --dport 68 -j RETURN");
	yexecl(NULL, "iptables -A MACFILTER_DROP -t nat -p udp --dport 67 -j RETURN");
	yexecl(NULL, "iptables -A MACFILTER_DROP -t nat -p tcp --dport 80 -j DNAT --to %s:%d", lan_ip, redirect_port);
	yexecl(NULL, "iptables -A MACFILTER_DROP -t nat -j MARK --set-mark 1");
}

static void delete_iptables_rule(void)
{
	yexecl(NULL, "iptables -D PREROUTING -t nat -i br0 -j MACFILTER");
	yexecl(NULL, "iptables -D INPUT -i br0 -m mark --mark 1 -j DROP");
	yexecl(NULL, "iptables -D FORWARD -i br0 -m mark --mark 1 -j DROP");
}

static void add_iptables(void)
{
	yexecl(NULL, "iptables -I PREROUTING -t nat -i br0 -j MACFILTER");
	yexecl(NULL, "iptables -I INPUT -i br0 -m mark --mark 1 -j DROP");
	yexecl(NULL, "iptables -I FORWARD -i br0 -m mark --mark 1 -j DROP");
}

static void add_sta_info(child_sta_t *sta, unsigned int week, unsigned int start_h, unsigned int start_m, unsigned int end_h, unsigned int end_m)
{
	child_sta_t *add_sta;

	add_sta = (child_sta_t *)malloc(sizeof(child_sta_t));
	add_sta->week = week;
	add_sta->start_h = start_h;
	add_sta->start_m = start_m;
	add_sta->end_h = end_h;
	add_sta->end_m = end_m;

	list_add_tail(&(add_sta->list), &(sta->list));
}

static int get_week(int y, int m, int d)
{
	static int t[] = {0, 3, 2, 5, 0, 3, 5, 1, 4, 6, 2, 4};

	y -= m < 3;

	return ((y + y/4 - y/100 + y/400 + t[m-1] + d) % 7);
}

static void get_operation_time(child_sta_t *sta, time_t c, time_t *s, time_t *e)
{
	int i;
	struct tm poll, *t;
	int today_week, week[7] = {SUN, MON, TUE, WED, THU, FRI, SAT};

	memset(&poll, 0, sizeof(struct tm));
	t = localtime(&c);

	poll.tm_year = t->tm_year;
	poll.tm_mon = t->tm_mon;
	poll.tm_mday = t->tm_mday;

	today_week = get_week(poll.tm_year + 1900, poll.tm_mon + 1, poll.tm_mday);

	for (i = 0; i <= 7; i++) {
		if (week[today_week] & sta->week) {
			poll.tm_hour = sta->start_h;
			poll.tm_min = sta->start_m;
			*s = mktime(&poll) + (i * CHILD_1DAY);
			poll.tm_hour = sta->end_h;
			poll.tm_min = sta->end_m;
			*e = mktime(&poll) + (i * CHILD_1DAY);

			if (*e < c) {
				today_week++;
				if (today_week >= 7)
					today_week = 0;
				continue;
			}
			break;
		} else {
			today_week++;
			if (today_week >= 7)
				today_week = 0;
		}
	}
}

static void get_child_time(member_t *member, time_t ctime)
{
	struct list_head *head;
	struct  list_head *temp;
	time_t stime, etime;
	child_sta_t *p;

	head = &(member->sta.list);

	member->s_time = 0;
	member->e_time = 0;

	list_for_each(temp, head) {
		p = list_entry(temp, child_sta_t, list);
		get_operation_time(p, ctime, &stime, &etime);
		if (member->s_time == 0 || (stime < member->s_time)) {
			member->s_time = stime;
			member->e_time = etime;
		}
	}
}

static int init_sta_member(member_t *member)
{
	int i, j, find, add_cnt = 0;
	time_t ctime;
	int entry, enable = 0, n;
	char buffer[64] = {0,}, value[64] = {0,};
	char *args[12] = {NULL,};
	child_sta_t *sta;

	/* get sta info */
	nvram_get_r_def("sta_protection_num", value, sizeof(value), "0");
	entry = strtoul(value, NULL, 10);

	for (i = 0; i < entry; i++) {
		find = 0;
		snprintf(buffer, sizeof(buffer), "sta_protection_list%d", i + 1);
		nvram_get_r_def(buffer, value, sizeof(value), "");

		if (value[0]) {
			n = ystrargs(value, args, _countof(args), ",", 0);
			if (n > 8) {
				enable = strtoul(args[8], NULL, 10);
				if (!enable)
					continue;

				for (j = 0; j <= add_cnt; j++) {
					if (strcmp(member[j].mac, args[0]) == 0) {
						find = 1;
						sta = &(member[j].sta);
						add_sta_info(sta, atoi(args[1]), atoi(args[2]), atoi(args[3]), atoi(args[4]), atoi(args[5]));
						break;
					}
				}

				if (find == 0) {
					snprintf(member[add_cnt].mac, sizeof(member[add_cnt].mac), "%s", args[0]);
					member[add_cnt].allow = atoi(args[6]);
					sta = &(member[add_cnt].sta);
					add_sta_info(sta, atoi(args[1]), atoi(args[2]), atoi(args[3]), atoi(args[4]), atoi(args[5]));
					add_cnt++;
				}
			}
		}
	}

	ctime = time(NULL);

	for (i = 0; i < add_cnt; i++)
		get_child_time(&member[i], ctime);

	return add_cnt;
}

static int get_sta_ipaddr(char *mac, char *ip, int ip_len)
{
	int ret = 0;
	FILE *fp = NULL;
	char line[80] = {0,};
	char *argv[6] = {NULL,};

	fp = fopen("/proc/net/arp", "r");
	if (fp) {
		fgets(line, sizeof(line), fp);
		while (fgets(line, sizeof(line), fp)) {
			if (ystrargs(line, argv, _countof(argv), " \t\n", 0) > 5) {
				if (strcmp(mac, argv[3]) == 0 && strcmp("0x0", argv[1])) {
					snprintf(ip, ip_len, "%s", argv[0]);
					ret = 1;
					break;
				}
			}
		}
		fclose(fp);
	}
	return ret;
}

static void set_child_guard(char *mac, int action)
{
	char macAddr[32], ipaddr[32];

	snprintf(macAddr, sizeof(macAddr), "%c%c:%c%c:%c%c:%c%c:%c%c:%c%c", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], mac[6], mac[7], mac[8], mac[9], mac[10], mac[11]);
	yexecl(NULL, "iptables -%s MACFILTER -t nat -m mac --mac-source %s -j MACFILTER_DROP", (action == CHILD_DENY)? "A" : "D", macAddr);
	if (action == CHILD_DENY) {
		if (get_sta_ipaddr(macAddr, ipaddr, sizeof(ipaddr)))
			yexecl(NULL, "conntrack -D -s %s", ipaddr);
		snprintf(macAddr, sizeof(macAddr), "%s", mac);
		yexecl(NULL, "iwpriv wlan0 del_sta %s", macAddr);
		/* handover delete sta */
		yexecl(NULL, "iwpriv wlan0-va3 del_sta %s", macAddr);
		yexecl(NULL, "iwpriv wlan1 del_sta %s", macAddr);
		yexecl(NULL, "iwpriv wlan1-va3 del_sta %s", macAddr);
		syslog(LOG_INFO, "[Child_Guard] Station %s Deny!.", macAddr);
	} else {
		syslog(LOG_INFO, "[Child_Guard] Station %s Allow!.", macAddr);
	}
}

static int write_pid(const char *pid_file)
{
	FILE *fp = NULL;
	int pid = 0;

	if (!pid_file || !pid_file[0])
        return 0;

	if ((fp = fopen(pid_file, "w"))) {
		pid = getpid();
		fprintf(fp, "%d\n", pid);
		fclose(fp);
   	}

	return pid;
}

static void sig_handler(int signo)
{
	switch(signo) {
		case SIGTERM:
			unlink(CHILD_GUARD_PID_FILE);
			exit(1);
			break;
	}
}

int main(int argc, char *argv[])
{
	struct timeval tv;
	int i, cnt, pid = 0;
	time_t ctime;

	yfcat(CHILD_GUARD_PID_FILE, "%d", &pid);
	if (pid > 0) {
		kill(pid, SIGTERM);
		fprintf(stderr, "child_guard has been restart\n");
	}

	write_pid(CHILD_GUARD_PID_FILE);
	signal(SIGTERM, sig_handler);

	check_ntp();

	if (access("/tmp/child_guard_ntp", F_OK)) {
		syslog(LOG_INFO, "[Child_Guard] NTP Sync Success!! Start Service.");
		yecho("/tmp/child_guard_ntp", "ntp_ok\n");
	}

	make_iptables_chain();
	delete_iptables_rule();
	add_iptables();

	memset(member, 0, sizeof(member_t) * CHILD_MAX);

	for (i = 0; i < CHILD_MAX; i++)
		INIT_LIST_HEAD(&(member[i].sta.list));

	cnt = init_sta_member(member);

	if (cnt == 0) {
		unlink(CHILD_GUARD_PID_FILE);
		return 0;
	}

	ctime = time(NULL);

	for (i = 0; i < cnt; i++) {
		if (member[i].s_time <= ctime && ctime < member[i].e_time) {
			member[i].run = 1;
			set_child_guard(member[i].mac, member[i].allow);
		} else {
			member[i].run = 0;
			set_child_guard(member[i].mac, member[i].allow == 1 ? CHILD_DENY : CHILD_ALLOW);
		}
	}

	while (1) {
		tv.tv_sec = 1;
		tv.tv_usec = 0;

		select(0, NULL, NULL, NULL, &tv);

		ctime = time(NULL);

		for (i = 0; i < cnt; i++) {
			if (member[i].run == 0 && (member[i].s_time <= ctime && ctime < member[i].e_time)) {
				member[i].run = 1;
				set_child_guard(member[i].mac, member[i].allow);
			} else if (member[i].run == 1 && (member[i].e_time < ctime)) {
				get_child_time(&member[i], ctime);
				if (!(member[i].s_time <= ctime && ctime < member[i].e_time)) {
					member[i].run = 0;
					set_child_guard(member[i].mac, member[i].allow == 1 ? CHILD_DENY : CHILD_ALLOW);
				}
			}
		}
	}

	unlink(CHILD_GUARD_PID_FILE);
	return 0;
}
