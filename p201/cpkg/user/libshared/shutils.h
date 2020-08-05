#ifndef _SHUTILS_H_
#define _SHUTILS_H_

#include <sys/types.h>
#include <unistd.h>

static inline char *strcat_r(const char *s1, const char *s2, char *buf)
{
	strcpy(buf, s1);
	strcat(buf, s2);
	return buf;
}

static inline char *strncat_r(const char *s1, const char *s2, char *buf, int len)
{
	snprintf(buf, len, "%s%s", s1, s2);
	return buf;
}

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

/*
 * Convert Ethernet address string representation to binary data
 * @param       a       string in xx:xx:xx:xx:xx:xx notation
 * @param       e       binary data
 * @return      TRUE if conversion was successful and FALSE otherwise
 */
extern int ether_atoe(const char *a, unsigned char *e);

/* Specify a delimiter between hex digits */
int ether_atoe_r(const char *a, unsigned char *e, const char *delim);

/*
 * Convert Ethernet address binary data to string representation
 * @param       e       binary data
 * @param       a       string in xx:xx:xx:xx:xx:xx notation
 * @return      a
 */
extern char *ether_etoa(const unsigned char *e, char *a);

extern const int IFUP;

char *inet_n2a(unsigned int addr);

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

#define __tostring_1(x...)	#x
#define __tostring(x...)	__tostring_1(x)

#endif
