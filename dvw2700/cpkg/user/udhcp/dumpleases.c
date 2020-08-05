#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <syslog.h>
#include <signal.h>
#include <errno.h>
#include <getopt.h>
#include <time.h>
#include "debug.h"
#include "leases.h"

#define REMAINING	0
#define ABSOLUTE	1

int main(int argc, char *argv[])
{
	FILE *fp;
	int i, c;
#ifdef LEASE_WRITE_THRU
	const char *optstr = "f:h";
#else
	int mode = REMAINING;
	const char *optstr = "arf:h";
#endif
	long expires;
	char file[255] = "/var/lib/misc/udhcpd.leases";
	struct dhcpOfferedAddr lease;
	struct in_addr addr;
	time_t curr, elapsed;
			
	static struct option options[] = {
#ifndef LEASE_WRITE_THRU
		{"absolute", 0, 0, 'a'},
		{"remaining", 0, 0, 'r'},
#endif
		{"file", 1, 0, 'f'},
		{"help", 0, 0, 'h'},
		{0, 0, 0, 0}
	};

	while (1) {
		int option_index = 0;
		c = getopt_long(argc, argv, optstr, options, &option_index);
		if (c == -1)
			break;

		switch (c) {
#ifndef LEASE_WRITE_THRU
		case 'a':
			mode = ABSOLUTE;
			break;
		case 'r':
			mode = REMAINING;
			break;
#endif
		case 'f':
			strncpy(file, optarg, 255);
			file[254] = '\0';
			break;
		case 'h':
		default:
			printf("Usage: dumpleases -f <file>%s\n\n",
#ifndef LEASE_WRITE_THRU
				" -[r|a]"
#else
				""
#endif
			);
			printf("  -f, --file=FILENAME             Leases file to load\n");
#ifndef LEASE_WRITE_THRU
			printf("  -r, --remaining                 Interepret lease times as time remaining\n");
			printf("  -a, --absolute                  Interepret lease times as expire time\n");
#endif
			exit(EXIT_SUCCESS);
			break;
		}
	}

	if (!(fp = fopen(file, "r"))) {
		perror("could not open input file");
		return 0;
	}

	printf("Mac Address       IP-Address      Expires %s\n",
#ifndef LEASE_WRITE_THRU
	       mode == REMAINING ? "in" : "at"
#else
	       "at"
#endif
	       );
	/*     "00:00:00:00:00:00 255.255.255.255 Wed Jun 30 21:49:08 1993" */
	elapsed = monotonic_sec();
	time(&curr);
	while (fread(&lease, sizeof(lease), 1, fp)) {
		for (i = 0; i < 6; i++) {
			printf("%02x", lease.chaddr[i]);
			if (i != 5)
				printf(":");
		}
		addr.s_addr = lease.yiaddr;
		printf(" %-15s", inet_ntoa(addr));
		expires = lease.expires;
		printf(" ");
#ifndef LEASE_WRITE_THRU
		if (mode == REMAINING) {
			if (!expires)
				printf("expired\n");
			else {
				if (expires > 60 * 60 * 24) {
					printf("%ld days, ",
					       expires / (60 * 60 * 24));
					expires %= 60 * 60 * 24;
				}
				if (expires > 60 * 60) {
					printf("%ld hours, ",
					       expires / (60 * 60));
					expires %= 60 * 60;
				}
				if (expires > 60) {
					printf("%ld minutes, ", expires / 60);
					expires %= 60;
				}
				printf("%ld seconds\n", expires);
			}
		} else
#endif
		{
			curr = (time_t)((long)curr + (long)(expires - elapsed));
			printf("%s", ctime(&curr));
		}
	}
	fclose(fp);

	return 0;
}
