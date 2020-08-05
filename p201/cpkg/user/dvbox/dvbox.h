#ifndef __dvbox_h_
#define __dvbox_h_

#include <unistd.h>
#include <linux/types.h>

struct applet_entry {
	const char *name;
	int (*main)(int argc, char **argv);
};

#define REG_APL_LEAF(name)    \
        static struct applet_entry __applet_entry__##name	\
        __attribute__((__section__("applet_entries")))		\
        __attribute__((__used__)) = { # name, name##_main }

#define REG_APL_LEAF2(name, entry)    \
        static struct applet_entry __applet_entry__##name	\
        __attribute__((__section__("applet_entries")))		\
        __attribute__((__used__)) = { # name, entry }

void error_msg_and_die(const char *fmt, ...);
int safe_strtoul(const char *nptr, unsigned long *ulptr, int base);
#if __BITS_PER_LONG > 32
int safe_atoi(const char *nptr, unsigned int *uptr, int base);
#else
#define safe_atoi(nptr, uptr, base) safe_strtoul(nptr, (unsigned long *)uptr, base)
#endif

#define uninitialized_var(x) x = x

#endif /* __dvbox_h_ */
