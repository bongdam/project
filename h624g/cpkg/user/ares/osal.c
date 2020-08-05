#ifndef WIN32
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif
#include "ares.h"
#ifdef WIN32
#include <iphlpapi.h>
#endif

#ifdef WIN32
#pragma comment( lib, "ws2_32.lib" )
#pragma comment( lib, "iphlpapi.lib" )

BOOL WSStart(void)
{
	WORD wVersionRequested;
	WSADATA wsaData;

	wVersionRequested = MAKEWORD(2, 2);
	if (WSAStartup(wVersionRequested, &wsaData) != 0) {
		/* Tell the user that we could not find a usable */
		/* WinSock DLL.                                  */
		return FALSE;
	}

	/* Confirm that the WinSock DLL supports 2.2.        */
	/* Note that if the DLL supports versions greater    */
	/* than 2.2 in addition to 2.2, it will still return */
	/* 2.2 in wVersion since that is the version we      */
	/* requested.                                        */

	if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2) {
		/* Tell the user that we could not find a usable */
		/* WinSock DLL.                                  */
		WSACleanup();
		return FALSE;
	}
	return TRUE;
}

int WSClose(void)
{
	return WSACleanup();
}

int inet_aton(const char *name, struct in_addr *ipaddr_ptr)
{
	int ipok = 0;
	unsigned long dots;
	unsigned long byte;
	unsigned long addr;

	addr = 0;
	dots = 0;
	for (;;) {

		if (!isdigit(*name))
			break;

		byte = 0;
		while (isdigit(*name)) {
			byte *= 10;
			byte += *name - '0';
			if (byte > 255)
				break;
			name++;
		}		/* Endwhile */
		if (byte > 255)
			break;
		addr <<= 8;
		addr += byte;

		if (*name == '.') {
			dots++;
			if (dots > 3)
				break;
			name++;
			continue;
		}
		/* Endif */
		if ((*name == '\0') && (dots == 3)) {
			ipok = 1;
		}
		/* Endif */
		break;

	}			/* Endfor */

	if (!ipok) {
		return 0;
	}
	/* Endif */
	if (ipaddr_ptr) {
		ipaddr_ptr->s_addr = htonl(addr);
	}
	/* Endif */
	return -1;

}

int WinGetNameServer(struct ares_options *options)
{
	int nservers = 0;
	IP_ADDR_STRING *addr;
	DWORD dwError;
	ULONG size = sizeof(FIXED_INFO);

	do {
		FIXED_INFO *info = (FIXED_INFO *) malloc(size);
		dwError = GetNetworkParams(info, &size);
		if (dwError == ERROR_SUCCESS) {
			for (addr = &info->DnsServerList; addr; addr = addr->Next)
				nservers++;

			if (nservers > 0) {
				options->servers =
				    REALLOC(options->servers, nservers * sizeof(struct in_addr));
				if (options->servers == NULL) {
					fprintf(stderr, "Out of memory!\n");
					return -1;
				}
				options->nservers = 0;
				for (addr = &info->DnsServerList; addr; addr = addr->Next)
					options->servers[options->nservers++].s_addr =
					    inet_addr(addr->IpAddress.String);
			}
		}
		free(info);
	} while (dwError == ERROR_BUFFER_OVERFLOW);

	return (nservers > 0) ? (0) : (-1);
}
#else
int read_resolver(unsigned int *ns, int siz)
{
	FILE *fp;
	char buffer[128];
	char *p, *plast;
	int i;
	unsigned int tmp;

	if (!ns || siz <= 0)
		return 0;

	for (i = 0; i < siz; i++)
		ns[i] = 0;

	i = 0;
	if ((fp = fopen("/etc/resolv.conf", "r"))) {
		while (fgets(buffer, sizeof(buffer), fp) && i < siz) {
			p = strtok_r(buffer, " \t\r\n", &plast);
			if (p && !strcasecmp(p, "nameserver")) {
				p = strtok_r(NULL, " \t\r\n", &plast);
				if (p != NULL) {
					tmp = inet_addr(p);
					if (tmp && tmp != (unsigned int)-1)
						ns[i++] = tmp;
				}
			}
		}
		fclose(fp);
	}
	return i;
}
#endif
