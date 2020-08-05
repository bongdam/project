#include <stdlib.h>
#include "libytool.h"

int yexecl(char *pathname, const char *arg, ...)
{
	va_list args;
	char buffer[256];
	char *p;
	int status = -1;
	char **argvp;

	va_start(args, arg);
	p = yvasprintf(buffer, sizeof(buffer), arg, args);
	va_end(args);

	if (p == NULL)
		return -1;

	if ((argvp = ybuildargv(p, NULL))) {
		status = yexecv(argvp, pathname, 0, NULL);
		free(argvp);
	}

	if (p != buffer)
		free(p);

	return status;
}
