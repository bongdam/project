#ifndef __APP_PERIODIC_WL_RESET_H__
#define __APP_PERIODIC_WL_RESET_H__

struct wl_reset_t {
	int start_ready;
	long next_poll_time;
	long try_limit_time;
	unsigned int interval;
	unsigned int start;
	unsigned int start_m;
	unsigned int end;
	unsigned int end_m;
	unsigned int bytes;
	unsigned int monitor;
};

struct row_data_t {
	unsigned long high;
	unsigned long low;
};

struct wl_data_t {
	struct row_data_t rx;
	struct row_data_t tx;
};

#endif
