#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "../libytool.h"

int LOG(const char *fmt, ...)
{
	char tmp[80];
	char *p;
	time_t now;
	struct tm *ptm;
	va_list ap;
	int nwritten = -1;

	va_start(ap, fmt);
	p = yvasprintf(tmp, sizeof(tmp), fmt, ap);
	va_end(ap);

	if (p != NULL) {
		time(&now);
		ptm = localtime(&now);
		nwritten = fprintf(stderr, "%02d:%02d:%02d : %s",
				ptm->tm_hour, ptm->tm_min, ptm->tm_sec, p);
		if (p != tmp)
			free(p);
	}

	return nwritten;
}

int main(void)
{
	LOG("%s(%d) Ytool Library Example for yvasprintf\n", __func__, __LINE__);
	return 0;
}
