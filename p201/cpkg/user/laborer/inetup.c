#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <syslog.h>
#include <netinet/in.h>
#include "notice.h"
#include <dvflag.h>
#include "instrument.h"
#include <shutils.h>
#include "conf.h"

#undef dprintf
extern long schedule(unsigned long, int (*)(long, unsigned long), int);
extern int pidof_dhcpc(const char *name);

enum {
	EV_LNKDOWN,
	EV_LNKUP,
	EV_BOUND,
	EV_UNBOUND,
	EV_EXPIRED,
	EV_MAX,
};

enum {
	ST_INETDOWN,
	ST_PLUGGED,
	ST_IFUP,
	ST_IFUP_BOUNCE,
	ST_INETREACH,
};

#ifndef NDEBUG
static const char *evname(int evt)
{
	static char buf[16];
	switch (evt) {
	case EV_LNKDOWN:
		return "LNKDOWN";
	case EV_LNKUP:
		return "LNKUP";
	case EV_BOUND:
		return "BOUND";
	case EV_UNBOUND:
		return "DECONF";
	case EV_EXPIRED:
		return "TIMEDOUT";
	default:
		snprintf(buf, sizeof(buf), "%d", evt);
		return buf;
	}
}

static const char *stname(int state)
{
	static char buf[16];
	switch (state) {
	case ST_INETDOWN:
		return "INETDOWN";
	case ST_PLUGGED:
		return "PLUGGED";
	case ST_IFUP:
		return "IFUP";
	case ST_IFUP_BOUNCE:
		return "BOUNCING";
	case ST_INETREACH:
		return "INETREACH";
	default:
		snprintf(buf, sizeof(buf), "%d", state);
		return buf;
	}
}
#endif

#define FSM(event, state) ((event << 8) + state)

static int tr_event(u_int event, u_int full_evt)
{
	switch (event) {
	case DF_WANLINK:
		return (event & full_evt) ? EV_LNKUP : EV_LNKDOWN;

	case DF_WANBOUND:
	case DF_WANIPFILE:
		return (event & full_evt) ? EV_BOUND : EV_UNBOUND;

	default:
		return EV_MAX;
	}
}

static int st = ST_INETDOWN;
static long tid;
static unsigned int fbound = DF_WANBOUND;
#ifndef NDEBUG
static int verbose;
#endif

static int inet_conn_fsm_expired(long id, struct notice_block *nb);

static int yoyo_dhcpc(void)
{
	int pid = pidof_dhcpc(conf_ifwan());
	if (pid > 1)
		return kill(pid, 0);
	return -1;
}

/* lower case: event unset
 * upper case: event set
 *                              +-------------+
 *                              |             |
 *         ---WANLINK---------- |  INETDOWN   |<----------------wanbound-------
 *        |                     |(not access- |                                |
 *        |    ---wanlink-----> | ible)       |-----------------WANBOUND---    |
 *        |   |          ^      +-------------+                            |   |
 *        |   |          |                                                 |   |
 *        |   |          |                                                 |   |
 *        |   |          |              -------- wanlink ----------------->|   |
 *        |   |          |             |         (stop timer)              |   |
 *        V   |          |             |                                   V   |
 *  +-------------+      |      +-------------+                       +-------------+
 *  |             |      |      | IFUP_BOUNCE |          ---WANLINK---|             |
 *  |   PLUGGED   |<- wanbound -|(half way to |         |             |    IFUP     |
 *  |(cable plugg-| (stop timer)| access by u-|         V             |(if configur-|
 *  | ed)         |      |       | plink)      |        /\            | ed)         |
 *  +-------------+      |      +-------------+        /  \           +-------------+
 *        |   ^          |__________|   ^             /    \                ^
 *        |   |         /\              |_________ Y / Send \               |
 *        |   |        /  \                          \ USR1 /               |
 *        |   |       /case\            (run timer)   \ ?  /                |
 *        |   |<_____/ flag \______________________    \  /                 |
 *        |   |      \ esac /                      |    \/                  |
 *        |   |       \    /                       |     |                  |
 *        |   |        \  /                         -----)----------------->|
 *        |   |         \/                               |                  |
 *        | wanbound     |                               |                  |
 *        |   |          |      +-------------+       N  |                  |
 *        |    ----------)------|             |<---------                   |
 *        |              |      |  INETREACH  |                             |
 *         ------WANBOUND+----->|(accessible -|-----------wanlink-----------
 *                              | via uplink) |
 *                              +-------------+
 */
static int inet_conn_do_fsm(struct notice_block *nb, int evt, u_int full_event)
{
	int yoyo, prev_st = st;

	if ((evt == EV_LNKUP) && (DF_INITED & full_event))
		yoyo = yoyo_dhcpc();
	else
		yoyo = -1;

	switch (FSM(evt, st)) {
	case FSM(EV_LNKUP, ST_INETDOWN):
	case FSM(EV_UNBOUND, ST_INETREACH):
		st = ST_PLUGGED;
		break;

	case FSM(EV_LNKDOWN, ST_PLUGGED):
	case FSM(EV_UNBOUND, ST_IFUP):
		st = ST_INETDOWN;
		break;

	case FSM(EV_BOUND, ST_INETDOWN):
	case FSM(EV_LNKDOWN, ST_INETREACH):
		st = ST_IFUP;
		break;

	case FSM(EV_BOUND, ST_PLUGGED):
		st = ST_INETREACH;
		break;

	case FSM(EV_LNKUP, ST_IFUP):
		if (yoyo)
			st = ST_INETREACH;
		else {
			st = ST_IFUP_BOUNCE;
			tid = schedule((unsigned long)nb,
				       (void *)inet_conn_fsm_expired, 1000);
		}
		break;

	case FSM(EV_UNBOUND, ST_IFUP_BOUNCE):
	case FSM(EV_LNKDOWN, ST_IFUP_BOUNCE):
		if (tid)
			tid = ({ itimer_cancel(tid, NULL); 0; });
		st = (evt == EV_UNBOUND) ? ST_PLUGGED : ST_IFUP;
		break;

	case FSM(EV_EXPIRED, ST_IFUP_BOUNCE):
		full_event &= (DF_WANLINK | fbound);
		if (full_event == (DF_WANLINK | fbound))
			st = ST_INETREACH;
		else if (full_event == DF_WANLINK)
			st = ST_PLUGGED;
		else if (full_event == fbound)
			st = ST_IFUP;
		else
			st = ST_INETDOWN;
		break;

	default:
		break;
	}

#ifndef NDEBUG
	if (verbose)
		diag_printf("%s %s -> %s\n", evname(evt), stname(prev_st), stname(st));
#endif
	if (st == ST_INETREACH && prev_st != st)
		dispatch_event(DF_INETUP, DF_INETUP, 0);
	else if (prev_st == ST_INETREACH && prev_st != st)
		dispatch_event(0, DF_INETUP, 0);

	return prev_st;
}

static int inet_conn_fsm_expired(long id, struct notice_block *nb)
{
	tid = 0;
	inet_conn_do_fsm(nb, EV_EXPIRED, dev_event_current());
	return 0;
}

static int inet_conn_cb(struct notice_block *nb, u_int event, u_int full_event)
{
	inet_conn_do_fsm(nb, tr_event(event, full_event), full_event);
	return NOTICE_DONE;
}

static struct notice_block inet_conn_link_nb = {
	.notice_call = inet_conn_cb,
	.concern = DF_WANLINK,
	.priority = 101,
};

static struct notice_block inet_conn_if_nb = {
	.notice_call = inet_conn_cb,
	.priority = 101,
};

static void __attribute__ ((constructor)) register_inet_conn_notice(void)
{
	u_int32_t f = dev_event_current();

	dev_event_chain_register(&inet_conn_link_nb);
	if (f & DF_WANLINK)
		inet_conn_do_fsm(&inet_conn_link_nb, tr_event(DF_WANLINK, f), f);
	fbound = conf_sdmz_test() ? DF_WANIPFILE : DF_WANBOUND;
	inet_conn_if_nb.concern = fbound;
	dev_event_chain_register(&inet_conn_if_nb);
	if (f & fbound)
		inet_conn_do_fsm(&inet_conn_if_nb, tr_event(fbound, f), f);
}
