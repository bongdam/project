#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <error.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <net/route.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <brdio.h>
       
extern unsigned int if_nametoindex (const char *name);

#define sin_addr(s) (((struct sockaddr_in *)(s))->sin_addr)

const int IFUP = (IFF_UP | IFF_RUNNING | IFF_BROADCAST | IFF_MULTICAST);

int
ifconfig(const char *name, int flags, char *addr, char *netmask)
{
	int s;
	struct ifreq ifr;
	struct in_addr in_addr, in_netmask, in_broadaddr;

	/* Open a raw socket to the kernel */
	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		goto err;

	/* Set interface name */
	strncpy(ifr.ifr_name, name, IFNAMSIZ);

	if (!strchr(name, ':')) {
		/* Set interface flags */
		if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0)
			goto err;
		if (flags)	/* Any other flag set should be kept - young */
			ifr.ifr_flags |= flags;
		else
			ifr.ifr_flags &= ~IFF_UP;
		if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0)
			goto err;
	}
	/* Set IP address */
	if (addr) {
		inet_aton(addr, &in_addr);
		sin_addr(&ifr.ifr_addr).s_addr = in_addr.s_addr;
		ifr.ifr_addr.sa_family = AF_INET;
		if (ioctl(s, SIOCSIFADDR, &ifr) < 0)
			goto err;
	}

	/* Set IP netmask and broadcast */
	if (addr && netmask) {
		inet_aton(netmask, &in_netmask);
		sin_addr(&ifr.ifr_netmask).s_addr = in_netmask.s_addr;
		ifr.ifr_netmask.sa_family = AF_INET;
		if (ioctl(s, SIOCSIFNETMASK, &ifr) < 0)
			goto err;

		in_broadaddr.s_addr = (in_addr.s_addr & in_netmask.s_addr) | ~in_netmask.s_addr;
		sin_addr(&ifr.ifr_broadaddr).s_addr = in_broadaddr.s_addr;
		ifr.ifr_broadaddr.sa_family = AF_INET;
		if (ioctl(s, SIOCSIFBRDADDR, &ifr) < 0)
			goto err;
	}

	close(s);

	return 0;

 err:
	close(s);
	perror(name);
	return errno;
}

static int
route_manip(int cmd, char *name, int metric, char *dst, char *gateway, char *genmask)
{
	int s;
	struct rtentry rt;

	/* Open a raw socket to the kernel */
	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		goto err;

	/* Fill in rtentry */
	memset(&rt, 0, sizeof(rt));
	if (dst)
		inet_aton(dst, &sin_addr(&rt.rt_dst));
	if (gateway)
		inet_aton(gateway, &sin_addr(&rt.rt_gateway));
	if (genmask)
		inet_aton(genmask, &sin_addr(&rt.rt_genmask));
	rt.rt_metric = metric;
	rt.rt_flags = RTF_UP;
	if (sin_addr(&rt.rt_gateway).s_addr)
		rt.rt_flags |= RTF_GATEWAY;
	if (sin_addr(&rt.rt_genmask).s_addr == INADDR_BROADCAST)
		rt.rt_flags |= RTF_HOST;
	rt.rt_dev = name;

	/* Force address family to AF_INET */
	rt.rt_dst.sa_family = AF_INET;
	rt.rt_gateway.sa_family = AF_INET;
	rt.rt_genmask.sa_family = AF_INET;

	if (ioctl(s, cmd, &rt) < 0)
		goto err;

	close(s);
	return 0;

 err:
	close(s);
	if (errno != EEXIST && errno != ESRCH)
		perror(name ? name : "route_manip");
	return errno;
}

int
route_add(char *name, int metric, char *dst, char *gateway, char *genmask)
{
	return route_manip(SIOCADDRT, name, metric, dst, gateway, genmask);
}

int
route_del(char *name, int metric, char *dst, char *gateway, char *genmask)
{
	return route_manip(SIOCDELRT, name, metric, dst, gateway, genmask);
}

unsigned int switch_port_status(int portno)
{
	struct phreq phr;
	int fd;

	if (portno < PH_MINPORT || portno > PH_MAXPORT)
		return 0;

	memset(&phr, 0, sizeof(phr));
	fd = open("/proc/brdio", O_RDWR);
	if (fd < 0)
		return 0;
	phr.phr_port = portno;
	if (ioctl(fd, PHGIO, &phr))
		perror("PHGIO");
	close(fd);
	return phr.phr_optmask;
}
