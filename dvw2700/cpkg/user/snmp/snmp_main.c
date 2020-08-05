#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/errno.h>
#include <unistd.h>
#include <getopt.h>
#include <netdb.h>
#include <wait.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <syslog.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <typedefs.h>

#include "snmp_main.h"
#include "agt_engine.h"
#include "cjhv_api.h"
#include "cjhv_mib.h"
#include "snmp_community.h"

int snmpAction = SNMP_NO_ACTION;

char *get_getcommunity()
{
    return dvsnmp_cfg.getcommunity;
}

char *get_setcommunity()
{
    return dvsnmp_cfg.setcommunity;
}

static void sigTermAgent(int sig)
{
	(void)sig;

	unlink(SNMP_AGENT_PID_FILE);
	exit(0);
}

static void printUsage(void)
{
    printf("usage: snmpd\n"
			" -h HELP"
			" -a [(s)tart|s(t)op] [Start | Stop] agent daemon\n"
			" -m [trap-type] [file-name|\'NULL\'] Send trap message\n"
			"\n");
}

static void load_config(void)
{
	char value[12] = {0,};

	nvram_get_r_def("snmp_get_community", dvsnmp_cfg.getcommunity, DVSNMP_MAX_COMMUNITY_LEN, "CJHV-ap-Read");
	nvram_get_r_def("snmp_set_community", dvsnmp_cfg.setcommunity, DVSNMP_MAX_COMMUNITY_LEN, "CJHV-ap-Write");
	nvram_get_r_def("snmp_trp_community", dvsnmp_cfg.trpcommunity, DVSNMP_MAX_COMMUNITY_LEN, "CJHV-ap-trap");

	nvram_get_r_def("snmp_port", value, sizeof(value), "20161");
	dvsnmp_cfg.snmpport = strtol(value, NULL, 10);
}

static void sigusr1_agent(int sig)
{
	if (access(PING_RST, F_OK) == 0)
		update_ping_result();
	unlink(PING_RST);
}

static int snmpAgentMain(void)
{
	struct pollfd pfd[3];
	int pid, res;
	char value[24] = {0,};
	int snmp_fd, enable = 0;
	struct in_addr nip;
    struct sigaction sa;

    sa.sa_handler = SIG_IGN;
    sa.sa_flags = 0;
    sigaction(SIGCHLD, &sa, NULL);

    signal(SIGUSR1, sigusr1_agent);

	nvram_get_r_def("snmp_enable", value,  sizeof(value), "1");
	enable = strtol(value, NULL, 10);

	if (!enable) {
		printf("Snmp agent mode is set disabled");
		return 0;
	}

    if ((pid = test_pid(SNMP_AGENT_PID_FILE)) > 1) {
        kill(pid, SIGTERM);
        unlink(SNMP_AGENT_PID_FILE);
        fprintf(stderr, "snmp has been restart\n");
    }

    /* Daemonize and log PID */
    /* Comment out daemon() to remove zombie process */
    if (daemon(0, 1) == -1) {
        perror("daemon");
        exit(errno);
    }

    load_config();
    init_CJHV_AP_MIB();
    global_variables_initial();

    /* SNMP-agent initialisation functions */
    set_community(dvsnmp_cfg.getcommunity);
    set_community(dvsnmp_cfg.setcommunity);
	ensure_communities();
	// snmp trap start
	snmptrapmain();

	/* Open the network */
	nip.s_addr = 0;
	nvram_get_r_def("OP_MODE", value, sizeof(value), "0");
	if (value[0] == '0') {
		nvram_get_r_def("IP_ADDR", value, sizeof(value), "0");
		nip.s_addr = inet_addr(value);
	}
	snmp_fd = snmp_open_connection(nip.s_addr, dvsnmp_cfg.snmpport);

    signal(SIGTERM, sigTermAgent);
    signal(SIGSEGV, sigTermAgent);
    write_pid(SNMP_AGENT_PID_FILE);

    pfd[0].fd = snmp_fd;
    pfd[0].events = POLLIN;

    for (;;) {
        res = poll(pfd, 1, 3000);
        switch (res) {
        case 0:
			if (snmpAction == SNMP_REBOOT) {
				printf("SNMP Message : System Reboot\n");
				syslog(LOG_INFO, "SNMP Message : System Reboot");
				system("reboot");
			}
			if (snmpAction == SNMP_FACTORY_RESET) {
				printf("SNMP Message : System Factory Reset\n");
				syslog(LOG_INFO, "SNMP Message : System Factory Reset");
				system("echo 1 > /proc/load_default");
			}
			if (snmpAction == SNMP_SOFTRESET_TRAP) {
				send_softReset_trap_message();
				nvram_get_r_def("softreset_result", value, sizeof(value), "2");
				snmpAction = (value[0] == '1') ? SNMP_REBOOT : SNMP_NO_ACTION;
			}
		    break;
        case -1:
            if (errno != EINTR)
                perror("poll");
            break;
        default:
            if (pfd[0].revents)
                snmp_process_message(snmp_fd);
            break;
        }
    }

	return 0;
}

int main(int argc, char *argv[])
{
    static int init = 0;
    int c, pid;
    TIL list;

    if (argc < 2) {
        printUsage();
        return 0;
    }

    if (init == 0) {
        INIT_TIL(list);
        init = 1;
    }

    while (TRUE) {
    	int option_index = 0;
        static const struct option arg_options[] = {
            {"help", no_argument, 0, 'h'},
            {"[start | stop] agent daemon", required_argument, 0, 'a'},
            {"Send trap message", required_argument, 0, 'm'},
            {0, 0, 0, 0}
        };

        c = getopt_long(argc, argv, "h::a:m:", arg_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'a':
            if (STRONGCMP('s', 'S')) {
                snmpAgentMain();
            } else if (STRONGCMP('t', 'T')) {
                if ((pid = test_pid(SNMP_AGENT_PID_FILE)))
                    kill(pid, SIGTERM);
                unlink(SNMP_AGENT_PID_FILE);
            }
            break;
        case 'm':
		if (argc < 3) {
			printUsage();
			return -1;
		} else {

		}
            break;
        default:
            printUsage();
            return 0;
        }
    } // end while

    return 0;
}
