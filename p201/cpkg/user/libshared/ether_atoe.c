#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <net/ethernet.h>

#define in_range(c, lo, up)  ((int)c >= lo && (int)c <= up)
#define isdigit(c)           in_range(c, '0', '9')
#define isxdigit(c)          (isdigit(c) || in_range(c, 'a', 'f') || in_range(c, 'A', 'F'))

static int mac_string_bin(const char *a, unsigned char *e, const char *delim)
{
	char *p = (char *)a;
	int i, n, separator;

	while (isxdigit(*a))
		a++;
	separator = *a;

	if (separator && strchr(delim, separator)) {
		for (i = 0; isxdigit(*p) && i < ETHER_ADDR_LEN; p++) {
			e[i++] = n = strtoul(p, &p, 16);
			if (n < 0 || n > 255)
				break;
			if ((i == ETHER_ADDR_LEN) && (*p != separator))
				return 1;
		}
	}
	return 0;
}

int ether_atoe_r(const char *a, unsigned char *e, const char *delim)
{
	char buf[20];

	if (strspn(a, "0123456789abcdefABCDEF") == 12) {
		char *p = buf;
		while (*a) {
			*p++ = *a++;
			*p++ = *a++;
			*p++ = ':';
		}
		*--p = '\0';
		a = buf;
	}
	return mac_string_bin(a, e, delim);
}

/*
 * Convert Ethernet address string representation to binary data
 * @param	a	string in xx:xx:xx:xx:xx:xx or xxxxxxxxxxxx notation
 * @param	e	binary data
 * @return	TRUE if conversion was successful and FALSE otherwise
 */
int ether_atoe(const char *a, unsigned char *e)
{
	return ether_atoe_r(a, e, "-:");
}
