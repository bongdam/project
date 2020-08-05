#ifdef SEND_GRATUITOUS_ARP
#include "apmib.h"
#include "mibtbl.h"
#endif
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#ifdef __CONFIG_LIB_SHARED__
#include <shutils.h>
#endif

#if defined(CONFIG_APP_BOA_AUTO_RECOVER)
#define CHECK_BOA_TIMEOUT 5
#endif

static unsigned int time_count;

#ifdef __CONFIG_LIB_SHARED__
static int testpidbyname(const char *command)
{
	pid_t self, *p;
	size_t i, num_pid = getpidbyname(command, &p);

	if (num_pid > 0) {
		self = getpid();
		for (i = 0; i < num_pid; i++) {
			if (self != p[i])
				break;
		}
		free(p);
	}

	return !!(num_pid > 0 && i < num_pid);
}

# if defined(APP_WATCHDOG)
# define is_watchdog_alive() testpidbyname("watchdog")
# endif
# if defined(CONFIG_APP_BOA_AUTO_RECOVER)
# define is_boa_alive() testpidbyname("boa")
# endif
#else	/* __CONFIG_LIB_SHARED__ */
#if defined(APP_WATCHDOG)
static int is_watchdog_alive(void)
{
	int is_alive = 0;
	int pid = -1;
	pid = find_pid_by_name("watchdog");
	if (pid > 0)
		is_alive = 1;
	return is_alive;
}
#endif

#if defined(CONFIG_APP_BOA_AUTO_RECOVER)
static int is_boa_alive(void)
{
	int pid = -1;
	pid = find_pid_by_name("boa");
	if (pid > 0)
		return 1;
	else
		return 0;
}
#endif
#endif	/* !__CONFIG_LIB_SHARED__ */

static void timeout_handler(int signo)
{
	time_count++;

	if (!(time_count % 1)) {
#if defined(APP_WATCHDOG)
		if (is_watchdog_alive() == 0) {
			//printf("watchdog is not alive\n");
			system("watchdog 1000&");
		}
#endif
	}
#if defined(CONFIG_APP_BOA_AUTO_RECOVER)
	if (!(time_count % CHECK_BOA_TIMEOUT)) {
		if (!is_boa_alive()) {
			system("boa");
		}
	}
#endif
	alarm(1);
}

int main(int argc, char **argv)
{
#ifdef SEND_GRATUITOUS_ARP
	if (!apmib_init()) {
		printf("Initialize AP MIB failed !\n");
		return -1;
	}
#endif
	signal(SIGALRM, timeout_handler);
	alarm(1);

	while (1) {
#ifdef SEND_GRATUITOUS_ARP
		checkWanStatus();
		sleep(1);
#else
		pause();
#endif
	}
	return 0;
}
