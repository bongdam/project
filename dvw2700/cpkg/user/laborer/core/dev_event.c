#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dvflag.h>
#include "select_event.h"
#include "notice.h"
#include "instrument.h"

#define BITS_PER_LONG 32

static const u_int32_t dev_event_mask = -1U;

static u_int32_t flg;
static u_int32_t oldflg;
static struct notice_block *dev_event_chain;

u_int32_t dev_event_current(void)
{
	return flg;
}

int dev_event_chain_register(struct notice_block *n)
{
	return notice_chain_register(&dev_event_chain, n);
}

int dev_event_chain_deregister(struct notice_block *n)
{
	return notice_chain_deregister(&dev_event_chain, n);
}

#define dev_event_fdset select_event_fdset_dfl

static int dev_event_read(struct select_event_base *base, int fd)
{
	u_int32_t changed;
	int i, n;

	if ((n = safe_read(fd, (void *)&flg, sizeof(flg))) <= 0)
		return n;

	flg &= dev_event_mask;
	changed = oldflg ^ flg;
	if (changed) {
		for (i = 0; i < BITS_PER_LONG; i++) {
			if (!(changed & (1 << i)))
				continue;
			notice_call_chain(&dev_event_chain, (u_int)(1 << i), flg, -1);
		}
	}

	oldflg = flg;
	return n;
}

static struct select_event_operation dev_event_op = {
	._fdset = dev_event_fdset,
	._read = dev_event_read,
};

static void __attribute__ ((constructor)) register_dev_event(void)
{
	int fd;

	fd = open("/proc/dvflag", O_RDWR);
	if (fd > -1) {
		ioctl(fd, DVFLGIO_SETMASK, &dev_event_mask);
		safe_read(fd, (void *)&flg, sizeof(flg));
		flg &= dev_event_mask;
		oldflg = flg;

		if (!select_event_alloc(fd, &dev_event_op,
				NULL, "file://proc/dvflag"))
			close(fd);
	} else
		perror(__func__);
}
