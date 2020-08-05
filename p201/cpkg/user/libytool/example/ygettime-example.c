#include <stdio.h>
#include "../libytool.h"

int main(void)
{
	struct timespec ts;
	float elapsed;

	ygettime(&ts);
	yfcat("/proc/uptime", "%f", &elapsed);
	printf("%lu:%ld\n%.2f\n", ts.tv_sec, ts.tv_nsec / 10000000, elapsed);

	return 0;
}
