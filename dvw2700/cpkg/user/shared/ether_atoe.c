#include <string.h>
#include <stdlib.h>
#include <net/ethernet.h>

#define in_range(c, lo, up)  ((int)c >= lo && (int)c <= up)
#define isdigit(c)           in_range(c, '0', '9')
#define isxdigit(c)          (isdigit(c) || in_range(c, 'a', 'f') || in_range(c, 'A', 'F'))

static int __ether_atoe(const char *a, unsigned char *e)
{
	char *c = (char *)a;
	int i = 0;

	memset(e, 0, ETHER_ADDR_LEN);
	for (;;) {
		e[i++] = (unsigned char)strtoul(c, &c, 16);
		if (*c != '-' && *c != ':')
			break;
		if (!*c++ || i == ETHER_ADDR_LEN || !isxdigit(*c))
			break;
	}
	return (i == ETHER_ADDR_LEN);
}

/*
 * Convert Ethernet address string representation to binary data
 * @param	a	string in xx:xx:xx:xx:xx:xx or xxxxxxxxxxxx notation
 * @param	e	binary data
 * @return	TRUE if conversion was successful and FALSE otherwise
 */
int ether_atoe(const char *a, unsigned char *e)
{
	const char *p;
	char str[20];
	int i, j;

	if (strlen(a) == 12) {
		for (i = 0, j = 0; i < 12; i += 2) {
			str[j++] = a[i];
			str[j++] = a[i + 1];
			str[j++] = ':';
		}
		str[--j] = 0;
		p = str;
	} else
		p = a;
	return (__ether_atoe(p, e));
}
