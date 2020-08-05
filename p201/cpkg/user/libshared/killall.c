#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
#include "shutils.h"

int killall(int signr, const char *command)
{
	pid_t self, *p;
	size_t i, num_pid = getpidbyname(command, &p);
	int sent;

	if (num_pid > 0) {
		self = getpid();
		for (i = sent = 0; i < num_pid; i++) {
			if (self == p[i])
				continue;
			sent += !kill(p[i], signr);
		}
		free(p);
		return sent;
	}

	return 0;
}
