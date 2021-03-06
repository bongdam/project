#ifndef _acl_write_h_
#define _acl_write_h_

struct dvCmdAcl_t {
	char cmd[8];    // flush, add, del
	char intf[8];   // eth1, br0, ...
	char dir[4];    // in, out
	rtl865x_AclRule_t rule;
	union {
		char chain[4];	// qos, dv, ...
		int chain_nr;
	} u;
	int keep_at_tail;
	int result;
};

#endif
