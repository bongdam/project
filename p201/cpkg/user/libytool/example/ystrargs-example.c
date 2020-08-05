#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../libytool.h"

int main(int argc, char **argv)
{
	char *p;
	int i, ac, empty = 0;
	char *ag[40];
	const char *BLANK = "_";

	if (argc < 3)
		return 0;
	if (argc > 3)
		empty = atoi(argv[3]);

	p = strdup(argv[1]);
	ac = ystrargs(p, ag, 40, argv[2], empty);
	for (i = 0; i < ac; i++)
		printf("|%s%s", ystrlen_zero(ag[i]) ? BLANK : ag[i], ((i + 1) < ac) ? "" : "\n");
	free(p);
	return 0;
}
