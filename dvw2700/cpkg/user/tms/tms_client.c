/******************************************************************************
**
**  Copyright: Davolink Inc. (since 2011)
**
**  File name: tms_client.c
**  Purpose:
**      Download S/W from HTTP/HTTPS server for autoupgrading,
**          it's similar as SWMS of DVW-2400N for SKBB.
**      It's only for CJ-HellowVision.
**      We are considering auto-configuration through the server in the future.
**
*******************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/mman.h>
#include <time.h>
#include <syslog.h>
#include <bcmnvram.h>
#include <libytool.h>
#include <dvflag.h>
#include <furl.h>
#include "tms_client.h"
#include "tms_misc.h"
#include "tms_client_private.h"
/*---------------------------------------------------------------------------*/

#define TMS_PID_FILE "/var/run/tms.pid"

static struct tms_t tms_main;
int commit;

void init_tmsinfo(struct tms_t *p)
{
	memset(p, 0, sizeof(struct tms_t));
}

variable vartbl[] = {
	// provision config
	{ "macaddr",                tms_setvar,  	(void *)(&tms_main.apms.macaddr[0]), 		sizeof(tms_main.apms.macaddr), 		STRING_T, 0},
	{ "apms_ip",                tms_setvar,  	(void *)(&tms_main.apms.apms_ip[0]), 		sizeof(tms_main.apms.apms_ip), 		STRING_T | FLG_INANY | FLG_DVNV | FLG_REBOOT, 0},
	{ "prov_ip",                tms_setvar,  	(void *)(&tms_main.apms.prov_ip[0]), 		sizeof(tms_main.apms.prov_ip), 		STRING_T | FLG_INANY | FLG_DVNV, 0},
	{ "cfgac",                  tms_cfg_setvar, (void *)(&tms_main.cfgac[0]), 				0, 									STRING_T | FLG_DVNV  , 0},
	{ "config_url",             tms_setvar,  	(void *)(&tms_main.apms.config_url[0]), 	sizeof(tms_main.apms.config_url),	STRING_T | FLG_DVNV  , 0},
	{ "config_ver",             tms_setvar,  	(void *)(&tms_main.cfver[0]),				sizeof(tms_main.cfver),				STRING_T | FLG_DVNV  , 0},
	{ "fwac",                   tms_setvar,  	(void *)(&tms_main.fwac[0]),				0,					 				STRING_T | FLG_DVNV  , 0},
	{ "firmware_url",           tms_setvar,  	(void *)(&tms_main.apms.firmware_url[0]),	sizeof(tms_main.apms.firmware_url), STRING_T | FLG_DVNV  , 0},
	{ "firmware_ver",           tms_setvar,  	(void *)(&tms_main.fwver[0]), 				sizeof(tms_main.fwver), 			STRING_T | FLG_DVNV  , 0},
	{ "prov_interval",          tms_setvar,  	(void *)(&tms_main.apms.prov_interval), 	sizeof(tms_main.apms.prov_interval),INT_T	 | FLG_DVNV, 0},
	{ "prov_stime",             tms_setvar,  	(void *)(&tms_main.apms.prov_stime[0]), 	sizeof(tms_main.apms.prov_stime), 	SPECIAL_T| FLG_DVNV, 0},
	{ "prov_etime",             tms_setvar,  	(void *)(&tms_main.apms.prov_etime[0]), 	sizeof(tms_main.apms.prov_etime), 	SPECIAL_T| FLG_DVNV, 0},
	{ "retry_count",            tms_setvar,  	(void *)(&tms_main.apms.retry_count), 		sizeof(tms_main.apms.retry_count), 	INT_T 	 | FLG_DVNV, 0},
	{ "retry_interval",         tms_setvar,  	(void *)(&tms_main.apms.retry_interval[0]),	sizeof(tms_main.apms.retry_interval),SPECIAL_T| FLG_DVNV, 0},
	// manufacture config
	{ "Manufacture", 			tms_check_cfg, 		NULL,						0, 							STRING_T, 0 },
	{ "root_id", 				tms_nvram_setvar, 	(void *)"SUPER_NAME", 		sizeof("SUPER_NAME")-1, 	STRING_T | FLG_WEB, 0},
	{ "root_pw", 				tms_nvram_setvar, 	(void *)"SUPER_PASSWORD", 	sizeof("SUPER_PASSWORD")-1, STRING_T | FLG_WEB, 0},
	{ "user_id", 				tms_nvram_setvar, 	(void *)"USER_NAME", 		sizeof("USER_NAME")-1, 		STRING_T | FLG_WEB, 0},
	{ "user_pw", 				tms_nvram_setvar, 	(void *)"USER_PASSWORD", 	sizeof("USER_PASSWORD")-1, 	STRING_T | FLG_WEB, 0},
	{ "web_port", 				tms_nvram_setvar, 	(void *)"webacl_port", 		0, 							STRING_T | FLG_FIREWALL, 0},
	{ "LAN1", 					tms_nvram_setvar, 	(void *)"x_port_1_config", 	0, 							STRING_T | FLG_REBOOT, 0},
	{ "LAN2", 					tms_nvram_setvar, 	(void *)"x_port_2_config", 	0, 							STRING_T | FLG_REBOOT, 0},
	{ "LAN3", 					tms_nvram_setvar, 	(void *)"x_port_3_config", 	0, 							STRING_T | FLG_REBOOT, 0},
	{ "LAN4", 					tms_nvram_setvar, 	(void *)"x_port_4_config", 	0, 							STRING_T | FLG_REBOOT, 0},
	/* TODO: we can add configuration parameters here in the fe */
	{ NULL, NULL, NULL, -1, -1, 0 }
};

#if 0
int rawdump(unsigned char *m, int len)
{
	const char *hexcode = "0123456789abcdef";
	char buf[64];
	unsigned char *p, *q;
	int quotient, remainder;
	int i, j, k, c;

	if (m == 0 || len <= 0)
		return -1;

	quotient = (len >> 4) + 1;
	remainder = len & 0xf;

	for (i = 0; i < quotient; i++) {
		if ((i + 1) == quotient) {
			memset(buf, ' ', sizeof(buf));
			k = remainder;
		} else
			k = 16;

		p = (unsigned char *)&buf[0];
		q = (unsigned char *)&buf[37];
		*p++ = ' ';
		*q++ = ' ';
		for (j = 0; j < k; j++) {
			if ((j % 4) == 0)
				*p++ = ' ';
			if ((j % 8) == 0)
				*q++ = ' ';
			c = *m++;
			*p++ = hexcode[(c >> 4) & 0xf];
			*p++ = hexcode[c & 0xf];
			if ((c < 0x20) || (c >= 0x7F))
				*q++ = '.';
			else
				*q++ = c;
		}
		*q = 0;
		printf("%s\n", buf);
	}
	printf("\n");
	return 0;
}
#endif


static void sig_term(int signo)
{
	unlink(TMS_PID_FILE);
	DEBUG("%s\n", "exit");
	syslog(LOG_INFO, "[TMS] daemon stop(signo:%d)",signo);
	_exit(-1);
}

static void sig_handler(int signo)
{
	int i;
	FILE *fp;

	printf("tmsmain cfg, make \"/var/tms_running_cfg\"\n");

	if ((fp = fopen("/var/tms_running_cfg", "w"))) {
		fprintf(fp, "cfgac [%s] \n",tms_main.cfgac);
		fprintf(fp, "cfver [%s] \n",tms_main.cfver);
		fprintf(fp, "fwac [%s] \n",tms_main.fwac);
		fprintf(fp, "fwver [%s] \n",tms_main.fwver);
		fprintf(fp, "apms_req_url [%s] \n",tms_main.apms_req_url);
		fprintf(fp, "cferr [%d] \n",tms_main.cferr);
		fprintf(fp, "fwerr [%d] \n\n",tms_main.fwerr);

		fprintf(fp, "apms.macaddr [%s] \n",tms_main.apms.macaddr);
		fprintf(fp, "apms.apms_ip [%s] \n",tms_main.apms.apms_ip);
		fprintf(fp, "apms.apms_port [%d] \n",tms_main.apms.apms_port);
		fprintf(fp, "apms.prov_ip [%s] \n",tms_main.apms.prov_ip);
		fprintf(fp, "apms.prov_port [%d] \n",tms_main.apms.prov_port);
		fprintf(fp, "apms.config_url [%s] \n",tms_main.apms.config_url);
		fprintf(fp, "apms.firmware_url [%s] \n",tms_main.apms.firmware_url);
		fprintf(fp, "apms.prov_interval [%d] \n",tms_main.apms.prov_interval);
		fprintf(fp, "apms.prov_stime [%d:%d:%d] \n",
				tms_main.apms.prov_stime[0], tms_main.apms.prov_stime[1], tms_main.apms.prov_stime[2]);
		fprintf(fp, "apms.prov_etime [%d:%d:%d] \n",
				tms_main.apms.prov_etime[0], tms_main.apms.prov_etime[1], tms_main.apms.prov_etime[2]);
		fprintf(fp, "apms.retry_count [%d] \n",tms_main.apms.retry_count);
		fprintf(fp, "apms.retry_interval:\n");
		for (i=0; i<tms_main.apms.retry_count; i++)
			fprintf(fp, "[%d] ",tms_main.apms.retry_interval[i]);

		fprintf(fp, "\n\nurl_req.ver [%s] \n",tms_main.url_req.ver);
		fprintf(fp, "url_req.mac [%s] \n",tms_main.url_req.mac);
		fprintf(fp, "url_req.downtype [%d] \n",tms_main.url_req.downtype);
		fprintf(fp, "url_req.model [%s] \n",tms_main.url_req.model);
		fprintf(fp, "url_req.vendor [%s] \n\n",tms_main.url_req.vendor);

		fprintf(fp, "wan_bw_kb %d\n", tms_main.chk.wan_bw_kb);
		fprintf(fp, "reboot_time [%02d:%02d]-[%02d:%02d] \n",
					tms_main.chk.reboot_time[0], tms_main.chk.reboot_time[1],
					tms_main.chk.reboot_time[2], tms_main.chk.reboot_time[3]);
		fprintf(fp, "reboot_retry %d \n", tms_main.chk.reboot_retry);
		fprintf(fp, "reboot_bw %d \n", tms_main.chk.reboot_bw);
		fprintf(fp, "down_retry_delay %d\n", tms_main.chk.down_retry_delay);
		fprintf(fp, "reboot_check_svc %d\n", tms_main.chk.reboot_check_svc);

		fclose(fp);
		printf("making file \"/var/tms_running_cfg\" in tms_main's data\n");
	}
}

static long apms_polling_calculation(long now, struct tms_t *p)
{
	struct tm now_clock, start_triger_clk, end_triger_clk;
	long t_start, t_end, time_gap, time_rand;
	long calc = 0;
	unsigned int interval = 0;
	now_clock = *(localtime(&now));
	start_triger_clk = now_clock;
	end_triger_clk = now_clock;

	start_triger_clk.tm_hour = p->apms.prov_stime[0];
	start_triger_clk.tm_min = p->apms.prov_stime[1];
	start_triger_clk.tm_sec = p->apms.prov_stime[2];

	end_triger_clk.tm_hour = p->apms.prov_etime[0];
	end_triger_clk.tm_min = p->apms.prov_etime[1];
	end_triger_clk.tm_sec = p->apms.prov_etime[2];

	t_start = mktime(&start_triger_clk);
	t_end = mktime(&end_triger_clk);

	calc = (t_end - t_start);
	if (calc == 0) {
		start_triger_clk.tm_hour = 1;
		start_triger_clk.tm_min = 0;
		start_triger_clk.tm_sec = 0;

		end_triger_clk.tm_hour = 6;
		end_triger_clk.tm_min = 0;
		end_triger_clk.tm_sec = 0;

		t_start = mktime(&start_triger_clk);
		t_end = mktime(&end_triger_clk);

		calc = (t_end - t_start);
	}

	time_rand = (rand() % calc);
	if (now < t_start) {
		time_gap = (t_start - now);
		return ((now + time_gap) + (p->apms.prov_interval*86400) + time_rand);
	} else {
		time_gap = (now - t_start);
		interval = p->apms.prov_interval;
		if (interval == 0)
			interval = 1;
		return (((now + interval*86400) - time_gap) + time_rand);
	}
}

int main(int argc, char *argv[])
{
	long now, next_poll_time;
	struct fwstat fbuf;
	char buffer[MAX_DOWN_DATA];
	int exp, status;
	int ntp = 0;
	time_t t;
	struct tm triger_time;
	int n, pid;
	char *mm;
	int psys_flag = 0;
	int first_wait;
	int is_First_PowerOn;

	if (!(n = safe_atoi(nvram_get("dv_tms_enabled"), 1))) {
		syslog(LOG_INFO, "[TMS] setup disabled...");
		exit(0);
	}

	tms_dbg = safe_atoi(nvram_get("dv_tms_dbg"), 0);

	if ((pid = test_pid(TMS_PID_FILE)) > 1) {
		kill(pid, SIGTERM);
		write_pid(TMS_PID_FILE);
		fprintf(stderr, "tms has been restart\n");
	} else
		write_pid(TMS_PID_FILE);
	DEBUG("%s\n", "start");

	signal(SIGUSR1, sig_handler);
	signal(SIGTERM, sig_term);
	signal(SIGALRM, SIG_IGN);

	init_tmsinfo(&tms_main);

	is_First_PowerOn = safe_atoi(nvram_get("First_Power_ON"), 1);

	while (!(ntp = check_ntp_client()) || access("/var/wan_ip", F_OK))
		my_sleep(1);

	DEBUG("%s\n", "start");
	initenv(&tms_main);

	dump_fwinfo("init", &tms_main);
	init_random_number();

	/* set initial polling delay */
	now = next_poll_time = time(NULL);
	first_wait = rand() % 60;
	DEBUG("just wait(%d sec)...\n", first_wait);
	syslog(LOG_INFO, "[TMS] start waiting...(%d sec)", first_wait);
	yecho(AUTOUP_STATE, "0"); //waiting for...
	my_sleep(first_wait);

	while (1) {
		/* get current system uptime then compare it with pollschedule */
		if (now >= next_poll_time) {
			make_build_msg(&tms_main);
			yecho(AUTOUP_STATE, "1"); //this name is referred in goahead.
			syslog(LOG_INFO, "[TMS] request apms(NTP:%s)", (ntp)?((ntp==1)?"OK":"OFF"):"Trying");
			/* get configuration file from server */
			status = 0;
			exp = 0;
			memset(&fbuf, 0, sizeof(fbuf));
			fbuf.fmem = buffer;
			fbuf.caplen = MAX_DOWN_DATA;
			if ((n = do_wget(&fbuf, buffer, &exp, MAX_TIMEO, &tms_main, WGET_APMS_REQ, &psys_flag, &status)) > 0) {
				psys_flag = 0;
				syslog(LOG_INFO, "[TMS] success: download apms config");

				dump_fwinfo("after download apms config", &tms_main);
				DEBUG("parse_config needs %s\n", (psys_flag) ? "REBOOT" : "NO reboot");
				if (letsgo_download_davo_config(&tms_main)) {
					yecho(AUTOUP_STATE, "2");
					status = 0;
					exp = 0;
					memset(&buffer[0], 0, sizeof(buffer));
					memset(&fbuf, 0, sizeof(fbuf));
					fbuf.fmem = buffer;
					fbuf.caplen = MAX_DOWN_DATA;
					if ((n = do_wget(&fbuf, buffer, &exp, MAX_TIMEO, &tms_main, WGET_REQ_CONFIG, &psys_flag, &status)) > 0) {
						nvram_unset("cferr");
						if (nvram_get("tmp_cfgac"))
							nvram_set("cfgac", nvram_get("tmp_cfgac"));
						if (nvram_get("tmp_config_ver"))
							nvram_set("config_ver", nvram_get("tmp_config_ver"));
						syslog(LOG_INFO, "[TMS] success: download davo config");
					}

					//restore cfgac
					if (!n || nvram_get("cferr")) {
						syslog(LOG_INFO, "[TMS] problem apply davo config: restore cfgac!");
						if (tms_main.cfgac[0])
							nvram_set("cfgac", tms_main.cfgac);
						else
							nvram_unset("cfgac");
					}
				}

				if (psys_flag & TMS_NEED_WEB) {
					syslog(LOG_INFO, "[TMS] web account apply.");
					restart_web();
				}

				if (psys_flag & TMS_NEED_FIREWALL) {
					syslog(LOG_INFO, "[TMS] webport apply.");
					system("sysconf firewall");
				}

				if (letsgo_need_download_firmware(&tms_main)) {
					yecho(AUTOUP_STATE, "3");
					status = 0;
					mm = mmap(NULL, MAX_FWSIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
					if (mm == MAP_FAILED) {
						perror("mmap");
						sig_term(0);
					}
					exp = 0;
					memset(&fbuf, 0, sizeof(fbuf));
					fbuf.fmem = mm;
					fbuf.caplen = MAX_FWSIZE;
					if ((n = do_wget(&fbuf, mm, &exp, MAX_TIMEO, &tms_main, WGET_REQ_FIRM, &psys_flag, &status)) > 0) {
						yecho(AUTOUP_UPGRADE, "1");
						yecho(AUTOUP_STATE, "4");
						/* write new S/W image to FLASH-MEM */
						DEBUG("image length %d\n", fbuf.rcvlen);
						if (!status && !(status = fw_dualize(&fbuf))) {
							status = fw_write(&fbuf, NULL, NULL);
							if (!status) {
								if (nvram_get("tmp_fwac"))
									nvram_set("fwac", nvram_get("tmp_fwac"));
								yecho(AUTOUP_UPGRADE, "2");
								munmap(mm, MAX_FWSIZE);
								mm = MAP_FAILED;
								t = time(NULL);
								strftime(buffer, sizeof(buffer), "%F %H:%M:%S", localtime(&t));

								syslog(LOG_INFO, "[TMS] success: download firmware");

								DEBUG("Write image successfully at %s\n", buffer);
								/* check service in use to reboot system */
								yecho("/var/apms_polling", "waiting restart(upgrade)...");
								if (is_First_PowerOn || check_service_idle(&tms_main)) {
									nvram_set("First_Power_ON", "0");
									nvram_commit();
									DEBUG("%s\n", "reboot system");
									my_sleep(1);
									yexecl(NULL, "reboot");
									break;
								}
							}
						}
						unlink(AUTOUP_UPGRADE);
						/* If upgrade succeed, never reach here */
						DEBUG("result;%s\n", fw_strerror(status));
					}
					//restore fwac
					syslog(LOG_INFO, "[TMS] problem apply firmware: restore fwac!");
					if (tms_main.fwac[0])
						nvram_set("fwac", tms_main.fwac);
					else
						nvram_unset("fwac");

					if (mm != MAP_FAILED)
						munmap(mm, MAX_FWSIZE);
				}

				if ((psys_flag & FLG_REBOOT) || (psys_flag & TMS_NEED_REBOOT)) {
					yecho(AUTOUP_STATE, "6");
					yecho("/var/apms_polling", "waiting restart(config)...");
					if (check_service_idle(&tms_main)) {
						DEBUG("%s\n", "reboot system");
						nvram_commit();
						my_sleep(1);
						yexecl(NULL, "reboot");
						break;
					}
				}
			}

			initenv(&tms_main);
			next_poll_time = apms_polling_calculation(now, &tms_main);
			syslog(LOG_INFO, "config download, next polling time is %ld sec after.\n", next_poll_time - now);
			DEBUG("config download, next polling time is %ld sec after.\n", next_poll_time - now);
			triger_time = *(localtime(&next_poll_time));

			syslog(LOG_INFO, "[TMS] apms next polling day is (%4d.%02d.%02d %02d:%02d:%02d)\n",
				triger_time.tm_year+1900, triger_time.tm_mon+1, triger_time.tm_mday,
				triger_time.tm_hour, triger_time.tm_min, triger_time.tm_sec);
			yecho("/var/apms_polling", "%4d.%02d.%02d %02d:%02d:%02d",
					triger_time.tm_year+1900, triger_time.tm_mon+1, triger_time.tm_mday,
					triger_time.tm_hour, triger_time.tm_min, triger_time.tm_sec);
		}
		if (is_First_PowerOn) {
			nvram_set("First_Power_ON", "0");
			commit++;
			is_First_PowerOn = 0;
		}
		yecho(AUTOUP_STATE, "5");
		if (commit) {
			nvram_commit();
			commit = 0;
		}
		my_sleep(60);
		now = time(NULL);
	}
	DEBUG("%s\n", "exit");

	return 0;
}
