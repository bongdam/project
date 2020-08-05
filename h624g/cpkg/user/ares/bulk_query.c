#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef WIN32
#include <winsock2.h>
#include <sys/timeb.h>
#include <process.h>
#else
#include <arpa/inet.h>
#endif
#include "ares.h"

#ifdef WIN32
BOOL WSStart(void);
int WSClose(void);
#endif

static int in_compar(const struct dns_bulk_result *r1,
		     const struct dns_bulk_result *r2)
{
	if (r1->ip == r2->ip)
		return 0;
	if (r1->ip > r2->ip)
		return 1;
	return -1;
}

int main(int argc, char **argv)
{
	struct dns_bulk_result *result;
	int rescnt;
	int i;
	int repeat_count = 1;
	struct in_addr addr[10];
#ifdef WIN32
	WSStart();
#endif
	//rescnt = res_gethostbyname(argv[argc - 1], addr, 10);
	//for (i = 0; i < rescnt; i++)
	//	printf("* %s\n", inet_ntoa(addr[i]));

	dns_bulk_query(&(argv[1]), argc - 1, &result, &rescnt, repeat_count);
	printf("dns_bulk_query result\n");
	for (i = 0; i < rescnt; i++) {
		printf("\t\t %s %s:%d %08x\n", result[i].host,
		       inet_ntoa(*((struct in_addr *)&(result[i].ip))),
		       ntohs(result[i].port), result[i].ip);
	}
	qsort(result, rescnt, sizeof(struct dns_bulk_result), (void *)in_compar);
	printf("dns_bulk_query result after sort\n");
	for (i = 0; i < rescnt; i++) {
		printf("\t\t %s %s:%d %08x\n", result[i].host,
		       inet_ntoa(*((struct in_addr *)&(result[i].ip))),
		       ntohs(result[i].port), result[i].ip);
	}

	if (result)
		free(result);
#ifdef WIN32
	WSClose();
#endif
	return 1;
}
