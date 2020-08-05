#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <bcmnvram.h>
#include <libytool.h>
#include "dvbox.h"

static void mirror_nvram_parse(int *on, int *from, int *to)
{
	int cnt;
	char val[12];
	char *args[3];

	nvram_get_r("mirror", val, sizeof(val));

	cnt = ystrargs(val, args, _countof(args), "_\t\r\n", 0);
	if (cnt == 3) {
		if (strcmp(args[0], "on") == 0)
			*on = 1;
		else
			*on = 0;
		*from = strtol(args[1], NULL, 10);
		*to = strtol(args[2], NULL, 10);
	}
}

static void mirror_usage(int argc)
{
	int on, from, to;

	fprintf(stderr, "Usage: mirror apply|clear\n");
	fprintf(stderr, "              set from to\n");
	if (argc == 1) {
		// print current setting
		mirror_nvram_parse(&on, &from, &to);
		fprintf(stderr, "current setting: %s", on?"on":"off");
		if (on)
			fprintf(stderr, " [%d]->[%d]", from, to);
		fprintf(stderr, "\n");

	}
	exit(EXIT_FAILURE);
}


static int mirror_main(int argc, char *argv[])
{
	int on, from, to;
	char cmd[12];

	if (argc < 2)
		mirror_usage(argc);

	if (strcmp(argv[1], "clear") == 0) {
		nvram_set("mirror", "off_0_0");
		nvram_commit();
		on = from = to = 0;
	} else if (strcmp(argv[1], "set") == 0) {
		if (argc < 4)
			mirror_usage(argc);
		on = 1;
		from = strtol(argv[2], NULL, 0);
		to = strtol(argv[3], NULL, 0);
		snprintf(cmd, sizeof(cmd), "on_%d_%d", from, to);
		nvram_set("mirror", cmd);
		nvram_commit();
	} else if (strcmp(argv[1], "print") == 0) {
		mirror_nvram_parse(&on, &from, &to);
		fprintf(stdout, "%d,%d,%d", on, from, to);
		return 0;
	} else if (strcmp(argv[1], "apply") == 0) {
		mirror_nvram_parse(&on, &from, &to);
	} else
		mirror_usage(argc);

	// apply mirror to system
	if (on)
		yfecho("/proc/rtl865x/mirrorPort", O_WRONLY, 0644, "mirror %d %d %d\n", 1<<from, 1<<from, 1<<to);
	else
		yfecho("/proc/rtl865x/mirrorPort", O_WRONLY, 0644, "mirror 0 0 0\n");

	return 0;
}
REG_APL_LEAF(mirror);
