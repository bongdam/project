#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/sysinfo.h>
#include <time.h>
#include <unistd.h>
#include <syslog.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <syslog.h>
#include <libytool.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/types.h>
#include <dvflag.h>
#include <bcmnvram.h>

#include "auto_reboot.h"

/*
    @purpose: after system running every 14day, check system status,
            and if idle, force rebooting.
    1. random sleep

    2. system uptime check
        if ( uptime > 14day)

    3. check day-time ( tuesday ~ fri 03:00~06:00 AM?)

    4. check wan port idle ?

    5. check wireless traffic during 5m, traffic <= 180kbps
*/
static int auto_r_debug_enabled;

static dv_variable dv_name_tbl[] = {
	{"autoreboot_userforce", "0"},
	{"auto_reboot_enable", "0"},
	{"auto_reboot_dbg", "0"},
	{"auto_reboot_on_idle", "1"},
	{"auto_uptime", "7d"},
	{"auto_wan_port_idle", "1"},
	{"auto_hour_range", "04:30-05:00"},
	{"auto_check_day", "1"},
	{"auto_bw_kbps", "1000"},
	{"auto_bw_mon_min", "1"},
	{"auto_sleep_ps_min", "15"},
	{"auto_sleep_random_min", "20"},
	{"autoreboot_week", "5-5"},
	{"op_mode", "0"},
	{"autoreboot_wancrc", "20"},
	{ NULL, "" }
};

static unsigned long long get_byte_counts(int pos)
{
    FILE *fp;
    char *tmp, *value;
    char buffer[512];
    unsigned long long cnt[2] = {0};
    int i;

    if((fp=fopen("/proc/asicCounter","r"))!=NULL) {
        i = 0;
        while(fgets(buffer, 512, fp)) {
            if(i==6) {
                value = buffer;
                tmp = strsep(&value, ":");
                ydespaces(value);
                tmp = strsep(&value, " ");
                cnt[0] = strtoull(tmp, NULL, 10);
                ydespaces(value);
                tmp = strsep(&value, " ");
                ydespaces(value);
                tmp = strsep(&value, " ");
                ydespaces(value);
                tmp = strsep(&value, " ");
                ydespaces(value);
                tmp = strsep(&value, " ");
                ydespaces(value);
                tmp = strsep(&value, " ");
                ydespaces(value);
                tmp = strsep(&value, " ");
                cnt[1] = strtoul(tmp, NULL, 10);
                ydespaces(value);
            }
            i++;
        }
        fclose(fp);
    }
	return (cnt[pos]);
}

static void load_auto_reboot_config()
{
	FILE *fp;
	char *argv[4];
	char buf[64];
	dv_variable *v;

	if ((fp = fopen("/var/config/auto_reboot", "r"))) {
		while (fgets(buf, sizeof(buf), fp)) {
			if (ystrargs(buf, argv, _countof(argv), " =\r\n", 0) < 1)
				continue;
			for (v = &dv_name_tbl[0]; v->name; v++) {
				if (!strcmp(v->name, argv[0]) && argv[1])
					sprintf(v->value, argv[1]);
			}
		}
		fclose(fp);
	}
}

char *get_auto_reboot_config(char *cfg_name)
{
	dv_variable *v;

	for (v = &dv_name_tbl[0]; v->name; v++) {
		if (!strcmp(v->name, cfg_name))
			return v->value;
	}
	return "";
}

static void sig_term(int signo)
{
	unlink(AUTO_REBOOT_PID_FILE);
	exit(-1);
}

static void sig_handler(int signo)
{
	auto_r_debug_enabled = !auto_r_debug_enabled;
}

static int test_pid(const char *pid_file)
{
	char path[64];
	int pid;

	if (yfcat(pid_file, "%d", &pid) != 1 || pid <= 0)
		return 0;
	sprintf(path, "/proc/%d/cmdline", pid);
	return (access(path, F_OK) == 0) ? pid : 0;
}

static void at_sys_reboot(unsigned long sys_wancrc)
{
	if(!is_watching_tv_status()) {
		nvram_set("x_autoreboot_success", "1");
		nvram_commit();
		syslog(LOG_INFO, "AUTO-REBOOT 시스템 강제 재 부팅");
		yexecl(NULL, "sh -c \"snmp -m 4 %lu &\"", sys_wancrc);
		sleep(2);
		yexecl(NULL, "reboot");
	} else {
		syslog(LOG_INFO, "AUTO-REBOOT TV 시청 중...");
		yexecl(NULL, "sh -c \"snmp -m 4 %lu traffic &\"", sys_wancrc);
	}
}

static void apply_default_ldap_conf(auto_r_conf_t *at_conf)
{
	char *s, *e, *saveptr, *sm, *em;
	char buf[80];
	int valid_s, valid_e;
	ldap_conf_t *pldap = &at_conf->ldap_cnf;
	int hour_unit = 0, min_unit = 0, day_unit = 0;

	pldap->auto_reboot_on_idle = atoi(get_auto_reboot_config("auto_reboot_on_idle"));

	sprintf(buf, get_auto_reboot_config("auto_uptime"));
	if (strchr(&buf[0], 'h') || strchr(&buf[0], 'H'))
		hour_unit = 1;
	else if (strchr(&buf[0], 'm') || strchr(&buf[0], 'M'))
		min_unit = 1;
	else
		day_unit = 1;

	pldap->uptime = (int)strtoul(&buf[0], NULL, 10);

	if (day_unit)
		pldap->uptime = pldap->uptime * 24 * 60;
	else if (hour_unit)
		pldap->uptime = pldap->uptime * 60;

	if (pldap->uptime == 0)
		pldap->uptime = DEFAULT_UPTIME;

    if (pldap->uptime > 30*24*60)
        pldap->uptime = 43200; //30day

	pldap->wan_port_idle = atoi(get_auto_reboot_config("auto_wan_port_idle"));

	sprintf(buf, get_auto_reboot_config("auto_hour_range"));
    s=strtok_r(buf, " \r\n\t:", &saveptr);
    sm=strtok_r(NULL, " \r\n\t-", &saveptr);
    e=strtok_r(NULL, " \r\n\t:", &saveptr);
    em=strtok_r(NULL, " \r\n\t", &saveptr);

	if ((s && e) && (valid_s = VALID_TIME(atoi(s))) >= 0 && (valid_e = VALID_TIME(atoi(e))) >= 0) {
		pldap->hour_range[0] = (valid_s == 24) ? 0 : valid_s;
		pldap->hour_range[1] = (valid_e == 24) ? 0 : valid_e;
        pldap->min_range[0] = atoi(sm);
        pldap->min_range[1] = atoi(em);
	} else {
        pldap->hour_range[0] = 4;
        pldap->hour_range[1] = 5;
        pldap->min_range[0] = 30;
        pldap->min_range[1] = 0;
	}
}

static char *ascminute(unsigned int min, char *buf)
{
	unsigned day, hour;
	int i = 0;

	day = min / 1440;
	min %= 1440;
	hour = min / 60;
	min %= 60;
	if (day)
		i = sprintf(buf, "%d일", day);
	if (hour)
		i += sprintf(&buf[i], "/%d시", hour);
	if (min || (day == 0 && hour == 0))
		sprintf(&buf[i], "/%d분", min);
	return ystrtrim(buf, " /");
}

void view_syslog(auto_r_conf_t *at_conf, int status, void *lparam, void *param)
{
	char buf[80] = "";
	ldap_conf_t *pldap = &at_conf->ldap_cnf;

	switch (status) {
	case 0:
		if (lparam)
			syslog(LOG_INFO, "AUTO-REBOOT %s %llu(kbps) 트래픽 사용 중(기준:%d kbps)",
			       "RX", (((*((unsigned long long *)lparam)*8)/1000)/60), at_conf->bw_kbps );
		break;
	case 2:
		syslog(LOG_INFO, "AUTO-REBOOT LDAP-ON_IDLE(%d) 설정으로 인해 종료",
		       pldap->auto_reboot_on_idle);
		break;
	case 3:
		syslog(LOG_INFO, "AUTO-REBOOT LDAP-WAN_PORT_IDLE(%d) 강제 재부팅",
		       pldap->wan_port_idle);
		break;
	case 4:
		syslog(LOG_INFO, "AUTO-REBOOT LDAP-WAN_PORT_IDLE(%d) 5분간 WAN 트래픽 확인 중",
		       pldap->wan_port_idle);
		break;
	case 5:
		syslog(LOG_INFO, "AUTO-REBOOT 지정된 요일과 시간 랜덤 주기로 확인");
		break;
	case 6:
		if (param && lparam)
			syslog(LOG_INFO, "AUTO-REBOOT %u분마다 %s 초과 확인(NTP:%s)",
			       at_conf->sleep_ps_min, ascminute(*((int *)param), buf),
			       (*((int *)lparam) == 1) ? "OK" : "NOT OK");
		break;
	case 7:
		if (lparam)
			syslog(LOG_INFO, "AUTO-REBOOT %s 후 확인 시작", ascminute(*((int *)lparam), buf));
		break;
	case 8:
		if (param && lparam && *((int *)param) != 0 && *((int *)lparam) == 0)
			sprintf(&buf[0], "(%02d-%02d)", pldap->hour_range[0], pldap->hour_range[1]);
		if (lparam)
			syslog(LOG_INFO, "AUTO-REBOOT %s %s",
			       (*((int *)param) == 0) ? "지정된 요일이 아님" :
			        (*((int *)lparam) == 0) ? "지정된 시간 아님." : "지정된 요일과 시간이 맞음", buf);
		break;
	case 9:
		syslog(LOG_INFO, "AUTO-REBOOT LDAP-WAN_PORT_IDLE(1) 3분간 WAN 트래픽 확인 중");
		break;
	case 10:
		syslog(LOG_INFO, "AUTO-REBOOT LDAP-WAN_PORT_IDLE(1) 1분간 WAN 트래픽 확인 중");
		break;
	case 11:
		if (lparam)
			syslog(LOG_INFO, "AUTO-REBOOT CRC %llu(Count), (기준:%d)", *((unsigned long long*)lparam), at_conf->wancrc);
		break;
	case 12:
		syslog(LOG_INFO, "AUTO-REBOOT 14일 초과 트래픽 체크 시작.");
		break;
	case 13:
		syslog(LOG_INFO, "AUTO-REBOOT NTP동기화 확인.");
		break;
	default:
		break;
	}
}

void auto_r_dbg_printf(char *fmt, ...)
{
	va_list ap;
	time_t t;
	struct tm *now;
	char t_buf[80];

	t_buf[0] = 0;
	if (time(&t) != ((time_t)-1)) {
		now = localtime(&t);
		if (now->tm_year >= 113)	//2013~
			sprintf(&t_buf[0], "[%02d:%02d:%02d]", now->tm_hour, now->tm_min, now->tm_sec);
	}

	printf("" RED_COLOR "%sAUTO_R" NORMAL_COLOR ": ", (t_buf[0] != 0) ? t_buf : "");
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
}

static int get_ldap_conf(auto_r_conf_t *at_conf, char *file_path)
{
	FILE *fp;
	char buf[80];
	char *saveptr, *saveptr2;
	char *n, *v;
	char *s, *e, *sm, *em;
	ldap_conf_t *pldap = &at_conf->ldap_cnf;
	int valid_s, valid_e;
	int set_check = 0;
	int hour_unit = 0, min_unit = 0, day_unit = 0;

	if (!file_path)
		return 0;

	if (!(fp = fopen(file_path, "r")))
		return 0;

	while (fgets(buf, sizeof(buf), fp)) {
		n = strtok_r(buf, " \r\n\t=", &saveptr);
		v = strtok_r(NULL, " \r\n\t=", &saveptr);
		if (!n || !v)
			continue;

		if (!strcasecmp(n, "auto_reboot_on_idle")) {
			pldap->auto_reboot_on_idle = (int)strtoul(v, NULL, 10);
			set_check |= 1;
		} else if (!strcasecmp(n, "auto_uptime")) {
			if (strchr(&v[0], 'h') || strchr(&v[0], 'H'))
				hour_unit = 1;
			else if (strchr(&v[0], 'm') || strchr(&v[0], 'M'))
				min_unit = 1;
			else
				day_unit = 1;

			pldap->uptime = (int)strtoul(&v[0], NULL, 10);

			if (day_unit)
				pldap->uptime = pldap->uptime * 24 * 60;
			else if (hour_unit)
				pldap->uptime = pldap->uptime * 60;

			if (pldap->uptime == 0)
				pldap->uptime = DEFAULT_UPTIME;

           if (pldap->uptime > 30*24*60)
                pldap->uptime = 43200; //30day

			set_check |= 2;
		} else if (!strcasecmp(n, "auto_wan_port_idle")) {
			set_check |= 4;
			pldap->wan_port_idle = (int)strtoul(v, NULL, 10);
		} else if (!strcasecmp(n, "auto_hour_range")) {
         	s=strtok_r(v, " \r\n\t:", &saveptr2);
    		sm=strtok_r(NULL, " \r\n\t-", &saveptr2);
    		e=strtok_r(NULL, " \r\n\t:", &saveptr2);
    		em=strtok_r(NULL, " \r\n\t", &saveptr2);
			if ((s && e) && (valid_s = VALID_TIME(atoi(s))) >= 0 && (valid_e = VALID_TIME(atoi(e))) >= 0) {
				set_check |= 8;
				pldap->hour_range[0] = (valid_s == 24) ? 0 : valid_s;
				pldap->hour_range[1] = (valid_e == 24) ? 0 : valid_e;
        		pldap->min_range[0] = atoi(sm);
        		pldap->min_range[1] = atoi(em);
			}
		}
	}
	fclose(fp);
	return set_check;
}

void init_config(auto_r_conf_t *at_conf)
{
	ldap_conf_t *pldap = &at_conf->ldap_cnf;
	char buf[80];
	char *sp, *s, *e;
	int start, end;

	at_conf->check_day = atoi(get_auto_reboot_config("auto_check_day"));
	at_conf->bw_kbps = atoi(get_auto_reboot_config("auto_bw_kbps"));
	at_conf->bw_monitor_min = atoi(get_auto_reboot_config("auto_bw_mon_min"));
	at_conf->sleep_ps_min = atoi(get_auto_reboot_config("auto_sleep_ps_min"));
	at_conf->sleep_radom_min = atoi(get_auto_reboot_config("auto_sleep_random_min"));
	at_conf->wancrc = atoi(get_auto_reboot_config("autoreboot_wancrc"));

	sprintf(buf, get_auto_reboot_config("autoreboot_week"));

	s = strtok_r(buf, " \r\n\t-", &sp);
	e = strtok_r(NULL, " \r\n\t-", &sp);
	if (s && e) {
		start = strtoul(s, NULL, 10);
		end = strtoul(e, NULL, 10);
		at_conf->start_day = (start <= end) ? start : end;
		at_conf->end_day = (start >= end) ? start : end;
	}
	AUTO_R_PRINT("(cfg)on_idle(%d) uptime(%d) wan_port_idle(%d) week:%02d-%02d (sun:0,mon:1...) hour:%02d-%02d(24unit)\n",
		     pldap->auto_reboot_on_idle,
		     pldap->uptime,
		     pldap->wan_port_idle, at_conf->start_day, at_conf->end_day, pldap->hour_range[0], pldap->hour_range[1]);

	AUTO_R_PRINT("(module_cfg) check_day(%d) bw_kbps(%d) bw_mon_min(%d) \n",
		     at_conf->check_day, at_conf->bw_kbps, at_conf->bw_monitor_min);
}

static int playing_reboot_calendar(auto_r_conf_t *auto_conf)
{
	time_t t;
	struct tm *now, poll;
	ldap_conf_t *pldap = &auto_conf->ldap_cnf;
	int d_day = 0, d_time = 0;
	int ok = 0;
	time_t ctime, stime, etime;

	memset(&poll, 0, sizeof(struct tm));

	if (time(&t)) {
		now = localtime(&t);
		if ((d_day = CHECK_DAY(auto_conf->check_day, now->tm_wday, auto_conf->start_day, auto_conf->end_day))) {
			ctime = time(NULL);
			poll.tm_year = now->tm_year;
			poll.tm_mon = now->tm_mon;
			poll.tm_mday = now->tm_mday;
			poll.tm_hour = pldap->hour_range[0];
			poll.tm_min = pldap->min_range[0];
			stime = mktime(&poll);

			poll.tm_hour = pldap->hour_range[1];
			poll.tm_min = pldap->min_range[1];
			etime = mktime(&poll);

			if (stime <= ctime && ctime < etime) {
				 d_time = 1;
				 ok = 1;
			}
		}
	}

	if (d_day && ok) {
		AUTO_R_PRINT("(status) d-day:%s, now:(%02dh:%02dm) in o'clock(H:%02d-%02d)=%s\n",
		     	(d_day) ? "ok" : "nok", now->tm_hour, now->tm_min, pldap->hour_range[0], pldap->hour_range[1],
		     	(ok) ? "go" : "wait");
	}

	return (ok);
}

static void my_sleep(int sec)
{
	int n;

	while ((n = sleep(sec))) {
		sec = n;
	};
}

void prev_traffic_check(unsigned long long *rx_prev_bytes)
{
	*rx_prev_bytes = get_byte_counts(DEV_STATS_POS_RX_BYTE);
}

void cur_traffic_check(unsigned long long *rx_cur_bytes)
{
	*rx_cur_bytes = get_byte_counts(DEV_STATS_POS_RX_BYTE);
}

int uptime_crc_check(auto_r_conf_t *auto_conf, unsigned long *psys_wancrc, int *crc_check)
{
	unsigned long long rx_crc = 0;

	rx_crc = get_byte_counts(DEV_STATS_POS_RX_CRC);
	*psys_wancrc = rx_crc;

	/* crc none check upper than uptime 14days */
	if (*crc_check) {
		view_syslog(auto_conf, 12, 0, 0);
		return 1;
	}

	view_syslog(auto_conf, 11, (void *)&rx_crc, 0);
	*crc_check = 1;
	if(rx_crc >= auto_conf->wancrc)
		return 1;
	else {
		yexecl(NULL, "sh -c \"snmp -m 4 %llu crc &\"", rx_crc);
		return 0;
	}
}

int running_yourTraffic(auto_r_conf_t *auto_conf, unsigned long sys_wancrc)
{
	unsigned long long rx_prev_bytes = 0, rx_cur_bytes = 0;
	unsigned long long rx_diff = 0;
	int condition;
	int wan_alive = 1;

	if ( (condition = (((auto_conf->bw_kbps*1000)/8)*60)) <= 0)
		condition = DEFAULT_TRAFFIC_BYTE*60;

	prev_traffic_check(&rx_prev_bytes);
	AUTO_R_PRINT("(status) check traffic during %d (min)\n", auto_conf->bw_monitor_min);
	view_syslog(auto_conf, 10, 0, 0);
	my_sleep(auto_conf->bw_monitor_min * 60);

	cur_traffic_check(&rx_cur_bytes);

	if ((rx_diff = (rx_cur_bytes - rx_prev_bytes)) <= condition) {
		view_syslog(auto_conf, 0, (void *)&rx_diff, 0);
		my_sleep(auto_conf->bw_monitor_min * 60);

		prev_traffic_check(&rx_prev_bytes);
		AUTO_R_PRINT("(status) check traffic during %d (min)\n", auto_conf->bw_monitor_min);
		view_syslog(auto_conf, 10, 0, 0);
		my_sleep(auto_conf->bw_monitor_min * 60);

		cur_traffic_check(&rx_cur_bytes);

		if ((rx_diff = (rx_cur_bytes - rx_prev_bytes)) <= condition) {
			view_syslog(auto_conf, 0, (void *)&rx_diff, 0);
			my_sleep(auto_conf->bw_monitor_min * 60);

	    	prev_traffic_check(&rx_prev_bytes);
			AUTO_R_PRINT("(status) check traffic during %d (min)\n", auto_conf->bw_monitor_min);
			view_syslog(auto_conf, 10, 0, 0);
			my_sleep(auto_conf->bw_monitor_min * 60);

			cur_traffic_check(&rx_cur_bytes);

			if ((rx_diff = (rx_cur_bytes - rx_prev_bytes)) <= condition) {
				wan_alive = 0;
	    	}
	    }

	}

	syslog(LOG_INFO, "Traffic Rx:%llu | %d in autoreboot(byte)", rx_diff, condition);
	AUTO_R_PRINT("(status) RX used %llu(byte) in %d(byte)\n", rx_diff, condition);
	view_syslog(auto_conf, 0, (void *)&rx_diff, 0);
	if (wan_alive)
		yexecl(NULL, "sh -c \"snmp -m 4 %lu traffic &\"", sys_wancrc);
	return wan_alive;
}

void ether_toa(char *val, unsigned char *mac)
{
	int i = 0, n = 0;
	char tmp[40], buf[40];

	buf[0] = 0;
	while (val[i] != 0 && i < 12) {
		buf[i] = tolower(val[i]);
		i++;
	}
	buf[i] = '\0';
	if ((n = strspn(buf, "0123456789abcdef")) == 12) {
		n = 0;
		for (i=0; i<6; i++) {
			n += sprintf(tmp, "%.*s", 2, &buf[n]);
			mac[i] = strtoul(tmp, NULL, 16);
		}
	}
}

static unsigned int random_min(int pool)
{
	char tmp[16] = {0,};
	unsigned char a[6] = {0,};
	time_t t;

	t = time(NULL);
	nvram_get_r("HW_NIC1_ADDR", tmp, sizeof(tmp));
	if (tmp[0]) {
		ether_toa(tmp, a);
		srand(t ^ ((a[3]<<16) + (a[4]<<8) + a[5]));
	}
	return (rand() % pool);
}

static void check_ntp(void)
{
	int fd, flag;

	while (1) {
		fd = open("/proc/dvflag", O_RDONLY);
		if (fd >= 0) {
			if (read(fd, (void *)&flag, sizeof(flag)) > 0) {
				if (flag & DF_NTPSYNC) {
					close(fd);
					break;
				}
			}
			close(fd);
		}
		sleep(1);
	}
}

static void check_uptime(unsigned int uptime, time_t start)
{
	time_t ctime;
	struct sysinfo sys_info;
	unsigned int min_to_sec = 0;

	if (uptime > 0)
		min_to_sec = MIN_TO_SEC(uptime);
	else
		min_to_sec = MIN_TO_SEC(DEFAULT_DAY * 24 * 60);

	while (1) {
		sysinfo(&sys_info);
		ctime = time(NULL);
		if ((start <= ctime) || (sys_info.uptime >= min_to_sec)) {
			break;
		}
		sleep(1);
	}
}

static void next_polling(time_t start)
{
	time_t ctime;

	while (1) {
		ctime = time(NULL);
		if (start <= ctime) {
			break;
		}
		sleep(1);
	}
}

static int get_week(int y, int m, int d)
{
	static int t[] = {0, 3, 2, 5, 0, 3, 5, 1, 4, 6, 2, 4};

	y -= m < 3;

	return ((y + y/4 - y/100 + y/400 + t[m-1] + d) % 7);
}

static void calc_random_time(int next_week, time_t *s, auto_r_conf_t *auto_conf)
{
	struct tm *now, triger_time;
	ldap_conf_t *pldap = &auto_conf->ldap_cnf;
	unsigned int min_to_sec = 0;
	unsigned int add_sec = 0, diff_sec = 3000;	// 50min
	time_t c_time, stime, etime;
	int today_week, week[7] = {SUN, MON, TUE, WED, THU, FRI, SAT};
	int i = 0;

	if (next_week)
		min_to_sec = MIN_TO_SEC(DEFAULT_DAY * 24 * 60);

	time(&c_time);
	now = localtime(&c_time);
	today_week = get_week(now->tm_year + 1900, now->tm_mon + 1, now->tm_mday);
	for (i = 0; i <= 7; i++) {
		if (week[today_week] == auto_conf->start_day) {
			now->tm_hour = pldap->hour_range[0];
			now->tm_min = pldap->min_range[0];
			stime = mktime(now) + (i * AUTO_1DAY);
			now->tm_hour = pldap->hour_range[1];
			now->tm_min = pldap->min_range[1];
			etime = mktime(now) + (i * AUTO_1DAY);

			if (etime < c_time) {
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

	if (etime > stime) {
		diff_sec = (etime - stime);
		if (diff_sec <= 600)
			diff_sec = (etime - stime) * 0.5;
		else
			diff_sec = (etime - stime) * 0.75;
	}

	if ((add_sec = random_min(diff_sec)) <= 0)
    	add_sec = diff_sec;

    *s = stime + add_sec;

    if (*s < c_time)
    	*s = c_time;

	*s += min_to_sec;

  	triger_time = *(localtime(s));
    syslog(LOG_INFO, "AUTO-REBOOT (%4d.%02d.%02d %02d:%02d:%02d) START",
			triger_time.tm_year + 1900, triger_time.tm_mon + 1, triger_time.tm_mday,
			triger_time.tm_hour, triger_time.tm_min, triger_time.tm_sec);
}

static void calc_uptime(unsigned int uptime, time_t *s)
{
	time_t t;
	struct tm *now, triger_time;
	unsigned int min_to_sec = 0;

	time(&t);
	now = localtime(&t);

	if (uptime > 0)
		min_to_sec = MIN_TO_SEC(uptime);
	else
		min_to_sec = MIN_TO_SEC(DEFAULT_DAY * 24 * 60);

	*s = mktime(now) + min_to_sec;

  	triger_time = *(localtime(s));
    syslog(LOG_INFO, "AUTO-REBOOT %4d.%02d.%02d %02d:%02d:%02d 또는 UPTIME(%u)후 동작주기 확인시작",
			triger_time.tm_year + 1900, triger_time.tm_mon + 1, triger_time.tm_mday,
			triger_time.tm_hour, triger_time.tm_min, triger_time.tm_sec, min_to_sec);
}

int main(int argc, char *argv[])
{
	int ntp, auto_reboot = 0;
	auto_r_conf_t at_conf;
	ldap_conf_t *pldap = &at_conf.ldap_cnf;
	int set_check = 0;
	int pid;
	int day = 0, check_day = 0;
	int userforce, crc_check = 0;
	unsigned long sys_wancrc = 0;
	time_t init_time = 0;
	struct timeval tv;

	load_auto_reboot_config();

	if (!atoi(get_auto_reboot_config("auto_reboot_enable"))) {
		fprintf(stderr, "autoreboot not enable\n");
		exit(1);
	}

	userforce = atoi(get_auto_reboot_config("autoreboot_userforce"));
	auto_r_debug_enabled = atoi(get_auto_reboot_config("auto_reboot_dbg"));

	signal(SIGTERM, sig_term);
	signal(SIGUSR1, sig_handler);

	apply_default_ldap_conf(&at_conf);

	if (!userforce) {
		if (!access("/var/ldap_autoreboot", F_OK))
			set_check = get_ldap_conf(&at_conf, "/var/ldap_autoreboot");
	}

	if (!userforce && !pldap->auto_reboot_on_idle) {
		view_syslog(&at_conf, 2, 0, 0);
		AUTO_R_PRINT("(status) auto_reboot force exit(auto_reboot_on_idle:\"N\")!!!\n");
		exit(0);
	}

	if ((pid = test_pid(AUTO_REBOOT_PID_FILE)) > 1) {
		kill(pid, SIGTERM);
		AUTO_R_PRINT("auto_reboot process has been restart\n");
	}

	ywrite_pid(AUTO_REBOOT_PID_FILE);

	/* start process */
	init_config(&at_conf);
	view_syslog(&at_conf, 7, (void *)&pldap->uptime, 0);

	check_ntp();
	view_syslog(&at_conf, 13, 0, 0);

	calc_uptime(pldap->uptime, &init_time);
	check_uptime(pldap->uptime, init_time);
	view_syslog(&at_conf, 5, 0, 0);

	calc_random_time(0, &init_time, &at_conf);
	next_polling(init_time);

	while (LOOP_MAIN) {
		tv.tv_sec = 1;
		tv.tv_usec = 0;

		select(0, NULL, NULL, NULL, &tv);

		if (playing_reboot_calendar(&at_conf)) {
			/* Tues~Friday & Fire Time */
			if (!pldap->wan_port_idle) {
				view_syslog(&at_conf, 3, 0, 0);
				auto_reboot = 1;
			} else {
				/* WAN traffic check */
				/* default uptime 7day upper crc check */
				if (uptime_crc_check(&at_conf, &sys_wancrc, &crc_check)) {
					if(!running_yourTraffic(&at_conf, sys_wancrc))
						auto_reboot = 1;
				}
			}

			if (auto_reboot && playing_reboot_calendar(&at_conf))
				at_sys_reboot(sys_wancrc);

			calc_random_time(1, &init_time, &at_conf);
			next_polling(init_time);
		}
	}

	return 0;
}