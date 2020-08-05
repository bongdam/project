#include <stdio.h>
#include "../libytool.h"

int main(void)
{
	char buffer[256];
	unsigned int dest;
	unsigned char dns[4];

	yfcat("/proc/net/route", "%*[^\n] %*s %x", &dest);
	printf("%08x\n", dest);

	yfcat("/etc/resolv.conf", "%*[^\n] %*s %hhd.%hhd.%hhd.%hhd",
		  &dns[0], &dns[1], &dns[2], &dns[3]);
	printf("%u.%u.%u.%u\n", dns[0], dns[1], dns[2], dns[3]);

	if (yfcat("/var/product_info", "%*[^\n] %*[^\n] %*s %[^\n]", buffer) > 0)
		printf("%s\n", buffer);

	return 0;
}
