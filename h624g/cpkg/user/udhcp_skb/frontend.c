#include <string.h>

extern int udhcpd_main(int argc, char *argv[]);
extern int udhcpc_main(int argc, char *argv[]);
extern int dhcpr_main(int argc, char *argv[]);

int main(int argc, char *argv[])
{
	int ret = 0;
	char *base = strrchr(argv[0], '/');
	
	if (strstr(base ? (base + 1) : argv[0], "dhcpd"))
		ret = udhcpd_main(argc, argv);
	else if (strstr(base ? (base + 1) : argv[0], "dhcpr"))
		ret = dhcpr_main(argc, argv);
	else
		ret = udhcpc_main(argc, argv);
	
	return ret;
}
