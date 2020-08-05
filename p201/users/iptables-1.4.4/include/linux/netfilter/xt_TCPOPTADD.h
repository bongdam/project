#ifndef _XT_TCPOPTADD_H
#define _XT_TCPOPTADD_H

struct xt_tcpoptadd_target_info {
	u_int8_t op;
	u_int8_t id;
	u_int8_t len;
	u_int8_t value[40];
};
#define TCPOP_ALGIN (4)
#define MAX_TCP_OPTION_LEN 60
#endif /* _XT_TCPOPTADD_H */
