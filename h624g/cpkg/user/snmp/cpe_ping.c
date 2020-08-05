#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/sysinfo.h>
#include <libytool.h>

#include "snmp_main.h"
#include "skbb_api.h"
#include "snmp_traptype.h"

#define CPEPING_PIDPATH 	"/var/run/snmp_cpeping.pid"
int trap_shot;

#define START   1
#define TIME    60

typedef struct {
	int	pktTimeout;
	int pktTimeoutcnt;
	int pktportno;
	int minPingTime;
	int avgPingTime;
	int	maxPingTime;
	char pktmac[32];
	char pktipaddr[32];
} _CPEPING_T;

_CPEPING_T CPEPING_T;

static void child_exit_handle(int sig)
{
	unlink(CPEPING_PIDPATH);
	exit(0);
}

static int cpe_ps_name(char *path)
{
	FILE *fp;

	if (!path)
		return -1;

	if ( (fp = fopen(path, "w")) ) {
		fprintf(fp, "%d", getpid());
		fclose(fp);
		return 1;
	}

	return 0;
}

void ping_init_setup()
{
	memset(&CPEPING_T, 0, sizeof(CPEPING_T));
}

void cpeping_trapinfo(char *msg, int msglen, int *n)
{
    *n += snprintf(&msg[*n], msglen-*n, "|lan_port=%d\r\n", CPEPING_T.pktportno);
    *n += snprintf(&msg[*n], msglen-*n, "cpe_mac=%s\r\n", CPEPING_T.pktmac);
    *n += snprintf(&msg[*n], msglen-*n, "cpe_ip=%s\r\n", CPEPING_T.pktipaddr);
	*n += snprintf(&msg[*n], msglen-*n, "rtt_min=%d\r\n", CPEPING_T.minPingTime);
	*n += snprintf(&msg[*n], msglen-*n, "rtt_avg=%d\r\n", CPEPING_T.avgPingTime);
	*n += snprintf(&msg[*n], msglen-*n, "rtt_max=%d\r\n", CPEPING_T.maxPingTime);
	*n += snprintf(&msg[*n], msglen-*n, "timeout=%d\r\n", CPEPING_T.pktTimeoutcnt);
}

int getPid(char *filename)
{
	struct stat status;
	char buff[100];
	FILE *fp;

	if (stat(filename, &status) < 0)
		return -1;
	fp = fopen(filename, "r");
	if (!fp)
		return -1;

	fgets(buff, 100, fp);
	fclose(fp);

	return (atoi(buff));
}

static void send_period_trap(int signo)
{
	int num, no, exist = 0, pid;
	char *cpetrap_mode, tmpBuf[80];
	int cpetrap_sec, trapshot;

	cpetrap_mode = getValue("x_cpeping_trap")? : "0";
	trapshot = atoi(cpetrap_mode);

	if(!trapshot)
		return;

	//siganl DHCP server to update lease file
	sprintf(tmpBuf, "/var/run/udhcpd.pid");
	pid = getPid(tmpBuf);
	if ( pid > 0)
		kill(pid, SIGUSR1);
	usleep(500000);

	if((num = initHostInfo())) {
		exist = 1;
		for(no = 0; no < num; no++)
			snmp_cpeping_test(no);
	}

	trap_shot = exist;
	cpetrap_sec = (atoi(getValue("x_cpetrap_time")? :"180") * 60);
	alarm(cpetrap_sec);
}

void initial_msg(char *msg, int msglen, int *n)
{
	memset(msg, 0, msglen);
	*n = 0;
}

static void snmp_uptime_trap(int per_sec, int *is_first)
{
	unsigned long c_timesec_snmp;
	struct sysinfo info;
	char *cpetrap_mode, wan_ip[32];
	int trapshot;
	FILE *fp;

	cpetrap_mode = getValue("x_cpeping_trap")? : "0";
	trapshot = atoi(cpetrap_mode);

	if(!trapshot) {
		*is_first = 0;
		return;
	}

	if((*is_first == 1))
		return;

	if (sysinfo(&info) != 0)
		return;

	if((fp = fopen("/var/wan_ip", "r"))) {
		fgets(wan_ip, sizeof(wan_ip), fp);
		ydespaces(wan_ip);
		fclose(fp);
	}

	if ( (*is_first == 0) && ((c_timesec_snmp = info.uptime)>= per_sec) && (strcmp(wan_ip, "0.0.0.0")) && get_wanport_phyconfig() ) {
		*is_first = 1;
		send_period_trap(START);
	}
}

int update_cpe_param(int paramID, int param_portno, char *param_addr, char *param_cpemac)
{
    FILE *fp;
    char pid_path[32], buf[52];

    snprintf(pid_path, sizeof(pid_path), "%s%d", CPEPING_RESULT_PATH, paramID);

    fp = fopen(pid_path, "r");

    if (!fp)
        return -1;

    fgets(buf, sizeof(buf), fp);
    sscanf(buf, "minPingTime=%d", &CPEPING_T.minPingTime);
    fgets(buf, sizeof(buf), fp);
    sscanf(buf,"avgPingTime=%d",&CPEPING_T.avgPingTime);
    fgets(buf, sizeof(buf), fp);
    sscanf(buf,"maxPingTime=%d",&CPEPING_T.maxPingTime);
    fgets(buf, sizeof(buf), fp);
    sscanf(buf,"pktTimeoutcnt=%d",&CPEPING_T.pktTimeoutcnt);
    fclose(fp);

    CPEPING_T.pktportno = param_portno;
	memcpy(CPEPING_T.pktmac, param_cpemac, sizeof(CPEPING_T.pktmac));
	memcpy(CPEPING_T.pktipaddr, param_addr, sizeof(CPEPING_T.pktipaddr));

	return 0;
}

void cpe_ping_init()
{
	struct sigaction sa;
	char buf[52];
	int n, msglen, is_first_trap = 0, flag = 0;
	unsigned long lanip = 0, lanmask = 0, cpeAddr = 0;
	char msg[1500];
	struct timeval tv;
	struct CPEList_t *p;
	int server_socket, client_socket, client_addr, client_addr_size, result;
	fd_set readfds;
	struct sockaddr_un server_addr;
	char buff_rcv[BUFF_SIZE];
	char *args[4];

	setuid(getuid());

	if ( cpe_ps_name(CPEPING_PIDPATH) < 1)
		exit(-1);

	sa.sa_handler = child_exit_handle;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sigaction(SIGTERM, &sa, 0);

	signal(SIGALRM, send_period_trap);
	signal(SIGUSR1, send_period_trap);
	msglen = sizeof(msg);
	initial_msg(msg, msglen, &n);

	snprintf(buf, sizeof(buf), "%s", getValue("IP_ADDR"));
	lanip = inet_addr(buf);
	snprintf(buf, sizeof(buf), "%s", getValue("SUBNET_MASK"));
	lanmask = inet_addr(buf);

	if(!access(FILE_SERVER, F_OK)) {
		yexecl( NULL, "rm -f %s", FILE_SERVER);
	}

	server_socket  = socket(PF_FILE, SOCK_STREAM, 0);
	if( server_socket == -1)
		exit(-1);

	if( fcntl(server_socket, F_SETFL, O_NONBLOCK ) == -1 ) {
		close(server_socket);
		exit(-1);
	}

	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sun_family = AF_UNIX;
	strcpy(server_addr.sun_path, FILE_SERVER);

	if( bind(server_socket, (struct sockaddr *)&server_addr, sizeof( server_addr) ) == -1 ) {
		close(server_socket);
		exit(-1);
	}

	if( listen(server_socket, 5) == -1 ) {
		close(server_socket);
		exit(-1);
	}

	while (START) {
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		FD_ZERO(&readfds);
		FD_SET(server_socket, &readfds);

       	result = select(server_socket + 1 , &readfds, NULL, NULL, &tv);

		switch(result) {
		    case -1:
		        break;
		    case 0 :
			    snmp_uptime_trap(TIME, &is_first_trap);
			    if (trap_shot && flag) {
				    send_cpeping_status_trap(msg, n);
				    trap_shot = 0;
				    flag = 0;
			    }
			    initial_msg(msg, msglen, &n);
		        break;
		    default :
			    if( FD_ISSET(server_socket, &readfds)) {
				    p = (struct CPEList_t *)malloc(sizeof(struct CPEList_t));
				    if (p == NULL) {
				    	break;
				    }
				    memset(p, 0, sizeof(struct CPEList_t));
				    client_addr_size = sizeof( client_addr);
				    if ((client_socket = accept(server_socket, (struct sockaddr *)&client_addr, (socklen_t *)&client_addr_size)) == -1) {
				    	close(client_socket);
				    	break;
				    }

					if (client_socket)
					    read(client_socket, buff_rcv, BUFF_SIZE);

				    if (ystrargs(buff_rcv, args, _countof(args), ", \r\t\n", 0) > 3) {
					    p->No = atoi(args[0]);
					    p->portno = atoi(args[1]);
					    snprintf(p->addr, sizeof(p->addr), "%s", args[2]);
					    snprintf(p->cpemac, sizeof(p->cpemac), "%s", args[3]);
				    }

				    ping_init_setup();
				    cpeAddr = inet_addr(p->addr);

				    if ( (lanip & lanmask) == (cpeAddr & lanmask) ) {
					    yexecl( NULL, "mping -c 10 -q -w 1000 -f %d %s", p->No, p->addr);
					    if(update_cpe_param(p->No, p->portno, p->addr, p->cpemac) == 0) {
						    cpeping_trapinfo(msg, msglen, &n);
						    if (trap_shot)
							    flag = 1;
					    }
				    }
				    close(client_socket);
				    free(p);
			    }
				break;
		}
    }
}
