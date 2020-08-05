#include "apmib.h"
#include "mibtbl.h"
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#ifdef CONFIG_RTL_HTTPS_REDIRECT
#include <netdb.h>
#endif

#if defined(CONFIG_APP_BOA_AUTO_RECOVER)
#define CHECK_BOA_TIMEOUT 5
#endif

static unsigned int time_count;

#if defined(APP_WATCHDOG)
static int is_watchdog_alive(void)
{
#ifdef __DAVO__
	static int pid;
	char buf[80];
	FILE *f;

	if (pid > 0) {
		snprintf(buf, sizeof(buf), "/proc/%d/status", pid);
		if ((f = fopen(buf, "r"))) {
			fscanf(f, "%*s %79s", buf);
			fclose(f);
			if (!strcmp(buf, "watchdog"))
				return 1;
		}
	}
	pid = find_pid_by_name("watchdog");
	return !!(pid > 0);
#else
	int is_alive = 0;
	int pid = -1;
	pid = find_pid_by_name("watchdog");
	if(pid > 0)
		is_alive = 1;
	return is_alive;
#endif
}

#endif

#if defined(CONFIG_APP_BOA_AUTO_RECOVER)
static int is_boa_alive(void)
{
	int pid = -1;
	pid = find_pid_by_name("boa");
	if(pid > 0)
		return 1;
	else
		return 0;
}
#endif

#ifdef CONFIG_RTL_HTTPS_REDIRECT
#define HTTP_REDIRECT_PROC_HOST_IP "/proc/http_redirect/host_ip"
static int is_http_reidrect_enabled()
{
	int enabled = 0;
	if(!apmib_get(MIB_HTTP_REDIRECT_ENABLED, (void *)&enabled))
		return 0;
	return enabled;
}

static void update_http_redirect_host_ip()
{
	unsigned char http_redirect_host[MAX_HTTP_URL_LEN]={0};
	char tmpBuf[256] = {0};
	char ip[INET_ADDRSTRLEN]={0};
	struct hostent *hptr;
	char **pptr;
	int i = 0;

	if(!apmib_get(MIB_HTTP_REDIRECT_HOST, (void *)http_redirect_host))
		return;

	snprintf(tmpBuf, sizeof(tmpBuf), "echo flush > %s", HTTP_REDIRECT_PROC_HOST_IP);
	system(tmpBuf);

	hptr=gethostbyname(http_redirect_host);
	if(hptr && hptr->h_addrtype == AF_INET){
		pptr = hptr->h_addr_list;
		inet_ntop(AF_INET,*pptr,ip,sizeof(ip));
		for(; *pptr != NULL; pptr++){
			inet_ntop(AF_INET,*pptr,ip,sizeof(ip));
			snprintf(tmpBuf, sizeof(tmpBuf), "echo add %s > %s", ip, HTTP_REDIRECT_PROC_HOST_IP);
			system(tmpBuf);
		}
	}
}
#endif

void timeout_handler()
{
	time_count++;
	if(!(time_count%1))
	{
#if defined(APP_WATCHDOG)
		if(is_watchdog_alive() == 0)
		{
			//printf("watchdog is not alive\n");
			system("watchdog 1000&");
		}
#endif

#ifdef CONFIG_RTL_HTTPS_REDIRECT
		if(is_http_reidrect_enabled())
		{
			update_http_redirect_host_ip();
		}
#endif

	}
#if defined(CONFIG_APP_BOA_AUTO_RECOVER)
	if(!(time_count%CHECK_BOA_TIMEOUT))
	{
		if(!is_boa_alive())
		{
			system("boa");
		}
	}
#endif
	if(!(time_count%60))
 	{
#ifdef CONFIG_RTL_8197F_VG
		if(isFileExist("/proc/check_swCore_tx_hang")){
#ifdef __DAVO__
			FILE *f = fopen("/proc/check_swCore_tx_hang", "r+");
			if (f) {
				fputs("rc\n", f);
				fclose(f);
			}
#else
			system("echo rc > /proc/check_swCore_tx_hang");
#endif
		}
#endif
	}
 	//alarm(1);
}

int main(int argc, char** argv)
{
	if ( !apmib_init()) {
		printf("Initialize AP MIB failed !\n");
		return -1;
	}
	//signal(SIGALRM,timeout_handler);
	//alarm(1);
	while(1)
	{
		#ifdef SEND_GRATUITOUS_ARP
		checkWanStatus();
		#endif

		#ifdef CONFIG_IPV6
		checkWanLinkStatus();
		#endif
		timeout_handler();
		sleep(1);
	}
}

