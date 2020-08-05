#ifndef _SHUTILS_H_
#define _SHUTILS_H_

#include <sys/types.h>
#include <unistd.h>

#define cprintf(fmt, args...) \
	do { \
		FILE *fp = fopen("/dev/console", "w"); \
		if (fp) { \
			fprintf(fp, fmt , ## args); \
			fclose(fp); \
		} \
	} while (0)

/* Debug print */
/* dprintf is glibc2 library function */
#ifdef DEBUG
# define dprint(fmt, args...) cprintf("%s: " fmt, __FUNCTION__ , ## args)
#else
# define dprint(fmt, args...) do {} while (0)
#endif /* DEBUG */

const char *base_name(const char *name);
int getpidbyname(const char *command, pid_t **ppid);
int killall(int signr, const char *command);
int waitfor(int fd, int timeout);

int ifconfig(const char *name, int flags, char *addr, char *netmask);
int route_add(char *name, int metric, char *dst, char *gateway, char *genmask);
int route_del(char *name, int metric, char *dst, char *gateway, char *genmask);

unsigned int switch_port_status(int portno);

extern const int IFUP;

struct scaled_octet {
	union {
		unsigned long long ull;
		unsigned long long N;
	};
	unsigned int F;
};

#define bin_scaled_octet(p)			\
({						\
	int __i;				\
	struct scaled_octet *__p;		\
						\
	__p = (p);				\
	__p->F = 0;				\
	for (__i = 0; __i < 4; __i++) {		\
		if (__p->N >= 1024) {		\
			__p->F = __p->N & 1023;	\
			__p->N >>= 10;		\
		} else				\
			break;			\
	}					\
	__i;					\
})

#define dec_scaled_octet(p)			\
({						\
	int __i;				\
	struct scaled_octet *__p;		\
						\
	__p = (p);				\
	__p->F = 0;				\
	for (__i = 0; __i < 4; __i++) {		\
		if (__p->N >= 1000) {		\
			__p->F = __p->N % 1000;	\
			__p->N /= 1000;		\
		} else				\
			break;			\
	}					\
	__i;					\
})

#endif
