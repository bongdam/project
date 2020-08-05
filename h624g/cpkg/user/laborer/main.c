#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "instrument.h"
#include "cmd.h"
#include "laborer.h"

/* jihyun@davo150623 jcode#5 */
extern struct labor_house family_smartreset;

struct labor_house *lfamily[] = {
	&family_smartreset,
	NULL
};

static void labor_house_init(void)
{
	int i;
	struct labor_house *family;

	for (i = 0; (family = lfamily[i]) != NULL; i++) {
		if (family->init)
			family->init();
	}
}

static void labor_house_poll(void)
{
	int i;
	struct labor_house *family;

	for (i = 0; (family = lfamily[i]) != NULL; i++) {
		if (family->enable && *(family->enable))
			family->poll();
	}
}

int link_watcher_init(void);
int link_watcher_read(int fd);
#ifdef __CONFIG_GNT2100__
int ont_channel(void);
int ont_recv(void);
#endif

int main(int argc, char **argv)
{
	fd_set rdset;
	struct timeval tv, *tvp;
	int fifo, nfd, maxfd, link;
	struct dline dl;
	int pid = fork();
#ifdef __CONFIG_GNT2100__
	int ont;
#endif
	if (pid < 0)
		return -errno;
	if (pid > 0)
		return 0;
	/* child */
	close(0);
	open("/dev/null", O_RDWR);
	//dup2(0, 1);
	dup2(0, 2);
	setsid();

	link = link_watcher_init();
	if (link < 0)
		return -1;
	fifo = init_fifo_server();
	if (fifo < 0) {
		close(link);
		return -1;
	}

	labor_house_init();

	maxfd = (fifo > link) ? fifo : link;
	dline_reset(&dl);
	while (1) {
		FD_ZERO(&rdset);
		FD_SET(fifo, &rdset);
		FD_SET(link, &rdset);
#ifdef __CONFIG_GNT2100__
		ont = ont_channel();
		if (ont > -1 && ({ FD_SET(ont, &rdset); 1; }) && maxfd < ont)
			maxfd = ont;
#endif
		tvp = itimer_iterate(&tv);
		nfd = select(maxfd + 1, &rdset, NULL, NULL, tvp);
		if (nfd > 0) {
#ifdef __CONFIG_GNT2100__
			if (ont > -1 && FD_ISSET(ont, &rdset))
				ont_recv();
#endif
			if (FD_ISSET(fifo, &rdset))
				fifo_server(fifo, &dl);
			if (FD_ISSET(link, &rdset))
				link_watcher_read(link);
		} else if (nfd == 0) {
			labor_house_poll();
		}
	}
	close(fifo);
	return 0;
}
