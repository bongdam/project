#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../libytool.h"

int main(void)
{
	char **argv;
	char buffer[256];
	int i;
	const char **p;
	const char *sample[] = {
		"a b c d",			// a b c d
		"a \"b c\" d",			// a "b c" d
		"a \\\"b c d",			// a \"b c d
		"a b\"c d\"d e",		// a b"c d"d e
		NULL
	};

	for (p = sample; *p; p++) {
		strcpy(buffer, *p);
		printf("%s:\t", buffer);
		argv = ybuildargv(buffer, NULL);
		if (argv) {
			for (i = 0; argv[i]; i++)
				printf("|%s%s", argv[i], argv[i + 1] ? "" : "|\n");
				free(argv);
		}
	}

	return 0;
}
