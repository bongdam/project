#ifndef __IFPORT_COUNTER__
#define __IFPORT_COUNTER__

struct ifport_counter_t {
	unsigned long long rx_bytes;
	unsigned long rx_upkts;
	unsigned long rx_mpkts;
	unsigned long rx_errors;

	unsigned long long tx_bytes;
	unsigned long tx_upkts;
	unsigned long tx_mpkts;
	unsigned long tx_errors;
};

// read from asicCounter(ethernet) : ifport_counter(NULL, port, &c)
// read from /proc/net/dev(linux interface) : ifport_counter(ifname, any, &c)
extern int ifport_counter(char *ifname, int eth_port, struct ifport_counter_t *c);

#endif
