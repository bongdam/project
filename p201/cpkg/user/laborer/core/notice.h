#ifndef __notice_h_
#define __notice_h_

#include <sys/types.h>

#define NOTICE_DONE		0x0000		/* Don't care */
#define NOTICE_OK		0x0001		/* Suits me */
#define NOTICE_STOP_MASK	0x8000		/* Don't call further */
#define NOTICE_BAD		(NOTICE_STOP_MASK|0x0002)

struct notice_block;
typedef	int (*notice_fn_t)(struct notice_block *nb,
			u_int event, u_int full_event);

struct notice_block {
	struct notice_block *next;
	notice_fn_t notice_call;
	unsigned long data;
	u_int concern;	/* event concerned */
	int priority; /* The bigger value, the higher priority */
};

int notice_chain_register(struct notice_block **nl,
		struct notice_block *n);

int notice_chain_deregister(struct notice_block **nl,
		struct notice_block *n);

int notice_call_chain(struct notice_block **nl,
		u_int event, u_int full_event, int nr_to_call);

int dev_event_chain_register(struct notice_block *n);
int dev_event_chain_deregister(struct notice_block *n);

u_int32_t dev_event_current(void);

struct nlmsghdr;
struct rtm_rx_handler;
typedef	int (*rtm_rx_func_t)(struct rtm_rx_handler *,
			struct nlmsghdr *, u_int);

struct rtm_rx_handler {
	struct rtm_rx_handler *next;
	rtm_rx_func_t rx_handler;
	unsigned long data;
	u_int mtype;	/* message type */
	int priority; /* The bigger value, the higher priority */
};

int rtm_rx_handler_register(struct rtm_rx_handler *h, u_int n);
void rtm_rx_handler_deregister(struct rtm_rx_handler *h, u_int n);
void rtm_rx_func_chain(struct nlmsghdr *nlh, u_int len, u_int mtype);

#endif	/* __notice_h_ */
