#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "dvbox.h"

extern struct applet_entry __start_applet_entries;
extern struct applet_entry __stop_applet_entries;

const char *base_name(const char *name)
{
	const char *cp = strrchr(name, '/');
	if (cp)
		return cp + 1;
	return name;
}

static int applet_compare(const struct applet_entry *m1, const struct applet_entry *m2)
{
	return strcmp(m1->name, m2->name);
}

static void __attribute__ ((constructor)) init_applet(void)
{
	size_t size = (size_t) & __stop_applet_entries - (size_t) & __start_applet_entries;
	qsort(&__start_applet_entries, size / sizeof(struct applet_entry),
	      sizeof(struct applet_entry), (void *)applet_compare);
}

int main(int argc, char **argv)
{
	struct applet_entry key, *applet;
	const char *applet_name = argv[0];
	size_t size;

	if (applet_name[0] == '-')
		applet_name++;
	applet_name = base_name(applet_name);

	size = (size_t) & __stop_applet_entries - (size_t) & __start_applet_entries;
	key.name = applet_name;
	applet = bsearch(&key, (void *)&__start_applet_entries, size / sizeof(struct applet_entry),
			 sizeof(struct applet_entry), (void *)applet_compare);

	if (applet)
		return applet->main(argc, argv);
	else
		fprintf(stderr, "Unknown applet name\n");
	exit(EXIT_FAILURE);
}
