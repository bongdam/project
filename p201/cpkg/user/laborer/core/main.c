#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include "instrument.h"
#include "cmd.h"

static void reap(int sig)
{
	do {
	} while (waitpid(-1, NULL, WNOHANG) > 0);
}

int main(int argc, char **argv)
{
	signal(SIGCHLD, reap);
	select_event_loop();
	return 0;
}
