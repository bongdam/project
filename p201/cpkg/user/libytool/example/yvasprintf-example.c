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

#define L_CRIT  -2	/* 31 RED */
#define L_ERR   -1	/* 35 MAGENTA */
#define L_WARN   1	/* 33 YELLOW */
#define L_INFO   2	/* 34 BLUE */
#define L_DBG    3

#define cprintf(fmt, args...) do { \
	FILE *fp = fopen("/dev/console", "w"); \
	if (fp) { \
		fprintf(fp, fmt , ## args); \
		fclose(fp); \
	} \
} while (0)

int yprintf(int level, const char *func, int line, const char *arg, ...)
{
	char *fg = "<D>", *rst = "\033[0m";
	va_list args;
	char buffer[128];
	char *p;

	va_start(args, arg);
	p = yvasprintf(buffer, sizeof(buffer), arg, args);
	va_end(args);
	if (p == NULL)
		return -1;
	switch (level) {
	case L_CRIT:
		fg = "\033[1;31m<C>"; break;
	case L_ERR:
		fg = "\033[1;35m<E>"; break;
	case L_WARN:
		fg = "\033[1;33m<W>"; break;
	case L_INFO:
		fg = "\033[1;34m<I>"; break;
	default:
		rst = "";
		break;
	}

	if (isatty(STDOUT_FILENO))
		printf("%s(%d): %s %s%s\n", func, line, fg, p, rst);
	else
		cprintf("%s(%d): %s %s%s\n", func, line, fg, p, rst);

        if (p != buffer)
                free(p);
	return 0;
}

int main(void)
{
        LOG("%s(%d) Ytool Library Example for yvasprintf\n", __func__, __LINE__);
        yprintf(L_CRIT, __func__, __LINE__, "Lorem ipsum dolor sit amet, cu vel cetero invidunt.");
        yprintf(L_ERR, __func__, __LINE__, "Nam ne dolorum complectitur, sed id congue mandamus evertitur");
        yprintf(L_WARN, __func__, __LINE__, "Ei sea epicuri gubergren scriptorem, agam officiis facilisis cu per, vim ex error euismod");
        yprintf(L_INFO, __func__, __LINE__, "Te mea congue doctus. Eum te dico putant ponderum");
        yprintf(L_DBG, __func__, __LINE__, "Id eam facilisi liberavisse, fugit maiorum recteque cum in.");
        return 0;
}
