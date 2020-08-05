#include <stdio.h>
#include <shutils.h>

/* ifconfig, route_add and route_del were moved into shared library.
 * 2015-04-14 15:56 young
 */
void
config_loopback(void)
{
	/* Bring up loopback interface */
	ifconfig("lo", IFUP, "127.0.0.1", "255.0.0.0");

	/* Add to routing table */
	route_add("lo", 0, "127.0.0.0", "0.0.0.0", "255.0.0.0");
}
