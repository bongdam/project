#define TLOG_PRINT(...)	\
	do {	\
		tlog_printf(__VA_ARGS__);	\
	} while (0)

extern int tlog_init(char *fname, int sz, int nfile);
extern int tlog_printf(const char *fmt, ...);

