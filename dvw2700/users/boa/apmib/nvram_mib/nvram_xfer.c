#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libytool.h>

#include "apmib.h"
#include "mibtbl.h"

#include <typedefs.h>
#include <bcmnvram.h>
#include "nvram_mib.h"

#define in_range(c, lo, up)  ((int)(c) >= lo && (int)(c) <= up)
#define isdigit(c)           in_range(c, '0', '9')
#define isxdigit(c)          (isdigit(c) || in_range(c, 'a', 'f') || in_range(c, 'A', 'F'))
#define islower(c)           in_range(c, 'a', 'z')

char *ystrncpy(char *dest, const char *src, size_t n)
{
	if (n > 0) {
		strncpy(dest, src, n--);
		dest[n] = '\0';
	}
	return dest;
}

char *yitoxa(char *dst, unsigned char *val, int valsize)
{
	const char *__xascii = "0123456789abcdef";
	char *p = dst;
	int c, i;

	for (i = 0; i < valsize; i++) {
		c = *val++;
		*p++ = __xascii[(c >> 4) & 0xf];
		*p++ = __xascii[c & 0xf];
	}
	*p = '\0';
	return dst;
}

int yxatoi(unsigned char *dst, const char *src, int len)
{
	unsigned int val;
	int c, i, ii;

	for (i = 0; i < len; i += 2) {
		for (val = ii = 0; ii < 2; ii++) {
			c = *src++;
			if (isdigit(c))
				val = (val << 4) + (int)(c - '0');
			else if (isxdigit(c))
				val = (val << 4) | (int)(c + 10 - (islower(c) ? 'a' : 'A'));
			else {
				nm_errno = ENM_INVAL;
				return 0;
			}
		}
		*dst++ = val;
	}

	return (*src) ? 0 : 1;
}

char *yunescape(char *str)
{
	char *p, *s;
	int c, bs = 0;

	for (p = s = str; (c = *s); s++) {
		if (bs)
			bs = 0;
		else if (c == '\\') {
			bs = 1;
			continue;
		}
		if (p != s)
			*p++ = c;
		else
			p++;
	}

	if (p != s)
		*p++ = '\0';

	return str;
}

char *ynvram_name(char *buf, size_t len, const char *wroot, unsigned int section)
{
	const char *p1 = "";
	char p2[32];
	int n;

	if (section & HW_SECT)
		p1 = "HW_";

	if (section & WLAN_SECT) {
		n = sprintf(p2, "WLAN%d_", wlan_idx);
		if (!(section & HW_SECT) && vwlan_idx > 0 && vwlan_idx <= NUM_VWLAN_INTERFACE)
			sprintf(&p2[n], "VAP%d_", vwlan_idx - 1);
	} else
		p2[0] = '\0';

	snprintf(buf, len, "%s%s%s", p1, p2, wroot);
	return buf;
}

int ynvram_putarray(const char *name, unsigned char *pbyte, unsigned short len)
{
	char *p = malloc((len << 1) + 1);

	if (p == NULL) {
		nm_errno = ENM_MEMORY;
		return FALSE;
	}
	ynvram_put("%s=%s", name, yitoxa(p, pbyte, len));
	free(p);
	return TRUE;
}

char *ynvram_get(const char *arg, ...)
{
	va_list args;
	char buffer[128];
	char *p, *q = NULL;

	va_start(args, arg);
	p = yvasprintf(buffer, sizeof(buffer), arg, args);
	va_end(args);

	if (p) {
		q = nvram_get(p);
		if (p != buffer)
			free(p);
	} else
		nm_errno = ENM_MEMORY;

	return q;
}

static int _ynvram_put(const char *fmt, va_list ap)
{
	char buf[128];
	va_list args;
	char *q, *p = buf;
	int n;

	va_copy(args, ap);
	n = vsnprintf(p, sizeof(buf), fmt, args);
	va_end(args);
	if (n >= (int)sizeof(buf) && (p = (char *)malloc(n + 1)))
		vsnprintf(p, n + 1, fmt, ap);

	if (p != NULL) {
		char *eq = strchr(p, '=');
		if (eq) {
			*eq++ = '\0';
			q = ystrtrim(yunescape(eq), " \f\n\r\t\v\"");
			if (nvram_match(p, q)) {
				nm_errno = ENM_IDENTICAL;
				n = 0;
			} else
				n = nvram_set(p, q);
		} else
			n = nvram_unset(p);

		if (p != buf)
			free(p);
		return n;
	} else
		nm_errno = ENM_MEMORY;
	return -1;
}

BOOL ynvram_put(const char *arg, ...)
{
	va_list args;
	int n;

	va_start(args, arg);
	n = _ynvram_put(arg, args);
	va_end(args);
	return n ? FALSE : TRUE;
}

char *ynvram_get_dfl(DFL_TYPE_T type, const char *name, char *buf, size_t len)
{
	const char *filepath = apmib_file_dfl(type);
	FILE *f;
	char *eq;

	if (filepath && (f = fopen(filepath, "r"))) {
		while (fgets(buf, len, f)) {
			eq = strchr(buf, '=');
			if (eq == NULL)
				continue;
			*eq++ = '\0';
			if (strcmp(name, ydespaces(buf)))
				continue;
			fclose(f);
			return ystrtrim(yunescape(eq), " \f\n\r\t\v\"");
		}
		fclose(f);
	}
	return NULL;
}
