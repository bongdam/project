#include <string.h>
#include "libytool.h"

int ystrargs(char *line, char *ag[], unsigned agsz, const char *delim, int empty)
{
	char *q, *p = line;
	unsigned i, ac = 0;

	if (line == NULL)
		return 0;

	while ((q = strsep(&p, delim))) {
		ydespaces(q);
		if (empty || *q) {
			if (ac < agsz)
				ag[ac++] = q;
		}
	}

	for (i = ac; i < agsz; i++)
		ag[i] = NULL;

	return (int)ac;
}
