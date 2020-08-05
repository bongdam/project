#include <stdio.h>
#include <net/ethernet.h>

/*
 * Convert Ethernet address binary data to string representation
 * @param	e	binary data
 * @param	a	string in xx:xx:xx:xx:xx:xx notation
 * @return	a
 */
char *ether_etoa(const unsigned char *e, char *a)
{
	const char *__xascii = "0123456789ABCDEF";
	char *c = a;
	int i;

	for (i = 0; i < ETHER_ADDR_LEN; i++) {
		if (i)
			*c++ = ':';
		*c++ = __xascii[(e[i] >> 4) & 0xf];
		*c++ = __xascii[e[i] & 0xf];
	}
	*c = '\0';
	return a;
}
