#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

char *ystrtrim(char *s, const char *exclude)
{
	const char *spanp;
	char *p, *q;
	char c, sc;

	if (!s || s[0] == 0)
		return s;

	/* skip leading spaces */
	for (p = s; (c = *p); p++) {
		spanp = (char *)exclude;
		do {
			if ((sc = *spanp++) == c)
				break;
		} while (sc != 0);
		if (sc == 0)
			break;
	}

	/* go to end of string */
	for (q = p; *q != 0; q++) ;
	/* truncate trailing spaces */
	while (p != q) {
		c = *(q - 1);
		spanp = (char *)exclude;
		do {
			if ((sc = *spanp++) == c) {
				*--q = 0;
				break;
			}
		} while (sc != 0);

		if (sc == 0)
			break;
	}

	if (p == s)
		return s;

	for (q = s; *p != 0; *s++ = *p++) ;
	*s = 0;
	return q;
}

char *ydespaces(char *s)
{
	return ystrtrim(s, " \f\n\r\t\v");
}
