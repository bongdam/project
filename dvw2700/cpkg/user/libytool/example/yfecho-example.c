#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../libytool.h"

#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]

int main(void)
{
	unsigned int lanIp = inet_addr("192.168.123.254");
	unsigned int mask = inet_addr("255.255.255.0");
	unsigned int dnsServer[2];
	unsigned int startIp, endIp;

	yfecho("wanip", O_WRONLY|O_CREAT|O_TRUNC, 0644, "%u.%u.%u.%u\n", NIPQUAD(mask));

	//yfecho("/proc/sys/net/ipv4/ip_forward", O_WRONLY|O_TRUNC, 0644, "1");

	dnsServer[0] = inet_addr("168.126.63.1");
	dnsServer[1] = inet_addr("168.126.63.2");
	yfecho("resolv.conf", O_WRONLY|O_CREAT|O_TRUNC, 0644, "nameserver %u.%u.%u.%u\n", NIPQUAD(dnsServer[0]));
	yfecho("resolv.conf", O_WRONLY|O_APPEND, 0644, "nameserver %u.%u.%u.%u\n", NIPQUAD(dnsServer[1]));

	startIp = htonl((ntohl(lanIp) & ~0xff) + 2);
	endIp = htonl((ntohl(lanIp) & ~0xff) + 100);

	yfecho("udhcpd.conf", O_WRONLY|O_CREAT|O_TRUNC, 0644,
		   "interface %s\n"
		   "server %u.%u.%u.%u\n"
		   "start %u.%u.%u.%u\n"
		   "end %u.%u.%u.%u\n"
		   "opt subnet %u.%u.%u.%u\n"
		   "opt router %u.%u.%u.%u\n"
		   "opt dns %u.%u.%u.%u\n",
		   "br0",
		   NIPQUAD(lanIp),
		   NIPQUAD(startIp),
		   NIPQUAD(endIp),
		   NIPQUAD(mask),
		   NIPQUAD(lanIp),
		   NIPQUAD(dnsServer[0]));

	return 0;
}
