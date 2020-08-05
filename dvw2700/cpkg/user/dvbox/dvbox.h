#ifndef __dvbox_h_
#define __dvbox_h_

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
int safe_strtoul(const char *nptr, unsigned int *ulptr, int base);
ssize_t safe_read(int fd, void *buf, size_t count);

#endif /* __dvbox_h_ */
