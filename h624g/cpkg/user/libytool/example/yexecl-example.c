#include <stdio.h>
#include "../libytool.h"

int main(void)
{
	yexecl(NULL, "iptables -t %s -nvL INPUT", "filter");

	yexecl(">/dev/null 2>&1", "iptables -t %s -F MINIUPNPD", "nat");

	yexecl(NULL, "sh -c \"echo Hello World!\"");

	return 0;
}
