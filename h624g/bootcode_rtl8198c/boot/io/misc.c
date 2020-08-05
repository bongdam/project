#include <linux/types.h>
#include "etherboot.h"
#include <stdarg.h>
#include <limits.h>

#define in_range(c, lo, up) ((int)c >= lo && (int)c <= up)
#define isupper(c) in_range(c, 'A', 'Z')
#define tolower(c) ({ int __x = (c); isupper(__x) ? (__x - 'A' + 'a') : __x;})

#ifndef false
#define false 0
#endif

#ifndef true
#define true (!false)
#endif

#define Putchar serial_outc

int strcasecmp(const char *s1, const char *s2)
{
	char c1, c2;
	while ((c1 = tolower(*s1++)) == (c2 = tolower(*s2++)))
		if (c1 == 0)
			return (0);
	return ((unsigned char)c1 - (unsigned char)c2);
}

typedef int __printf_fun(const char *fmt, ...);

/*----------------------------------------------------------------------*/
/*----------------------------------------------------------------------*/
/* Write single char to output                                          */

static void diag_write_char(char c)
{
	/* Translate LF into CRLF */
	if (c == '\n')
		Putchar('\r');
	Putchar(c);
}

// Default wrapper function used by diag_printf
static void _diag_write_char(char c, void **param)
{
	diag_write_char(c);
}

static void (*_putc)(char c, void **param) = _diag_write_char;

/*----------------------------------------------------------------------*/
/*----------------------------------------------------------------------*/
static char *put_dec_trunc8(char *buf, unsigned r)
{
	unsigned q;

	/* Copy of previous function's body with added early returns */
	while (r >= 10000) {
		q = r + '0';
		r  = (r * (unsigned long long)0x1999999a) >> 32;
		*buf++ = q - 10*r;
	}

	q      = (r * 0x199a) >> 16;	/* r <= 9999 */
	*buf++ = (r - 10 * q)  + '0';
	if (q == 0)
		return buf;
	r      = (q * 0xcd) >> 11;	/* q <= 999 */
	*buf++ = (q - 10 * r)  + '0';
	if (r == 0)
		return buf;
	q      = (r * 0xcd) >> 11;	/* r <= 99 */
	*buf++ = (r - 10 * q) + '0';
	if (q == 0)
		return buf;
	*buf++ = q + '0';		 /* q <= 9 */
	return buf;
}

static void put_dec_full4(char *buf, unsigned q)
{
	unsigned r;
	r      = (q * 0xccd) >> 15;
	buf[0] = (q - 10 * r) + '0';
	q      = (r * 0xcd) >> 11;
	buf[1] = (r - 10 * q)  + '0';
	r      = (q * 0xcd) >> 11;
	buf[2] = (q - 10 * r)  + '0';
	buf[3] = r + '0';
}

static unsigned put_dec_helper4(char *buf, unsigned x)
{
        unsigned int q = (x * (unsigned long long)0x346DC5D7) >> 43;
        put_dec_full4(buf, x - q * 10000);
        return q;
}

static char *put_dec(char *buf, unsigned long long n)
{
	unsigned int d3, d2, d1, q, h;

	if (n < 100*1000*1000)
		return put_dec_trunc8(buf, n);

	d1  = ((unsigned int)n >> 16); /* implicit "& 0xffff" */
	h   = (n >> 32);
	d2  = (h      ) & 0xffff;
	d3  = (h >> 16); /* implicit "& 0xffff" */

	q   = 656 * d3 + 7296 * d2 + 5536 * d1 + ((unsigned int)n & 0xffff);
	q = put_dec_helper4(buf, q);

	q += 7671 * d3 + 9496 * d2 + 6 * d1;
	q = put_dec_helper4(buf+4, q);

	q += 4749 * d3 + 42 * d2;
	q = put_dec_helper4(buf+8, q);

	q += 281 * d3;
	buf += 12;
	if (q)
		buf = put_dec_trunc8(buf, q);
	else while (buf[-1] == '0')
		--buf;
	return buf;
}

static int _cvt(unsigned long long val, char *buf, long radix, char *digits)
{
	char temp[80];
	char *cp = temp;
	int length = 0;

	if (val == 0) {
		/* Special case */
		*cp++ = '0';
	} else if (radix != 10) {
		int mask = radix - 1;
		int shift = 3;
		if (radix == 16) shift = 4;
		do {
			*cp++ = digits[((unsigned char)val) & mask];
			val >>= shift;
		} while (val);
	} else {
		cp = put_dec(cp, val);
	}
	while (cp != temp) {
		*buf++ = *--cp;
		length++;
	}
	*buf = '\0';
	return (length);
}

#define is_digit(c) ((c >= '0') && (c <= '9'))

static int _vprintf(void (*putc)(char c, void **param), void **param, const char *fmt, va_list ap)
{
	char buf[sizeof(long long) * 8];
	char c, sign, *cp = buf;
	int left_prec, right_prec, zero_fill, pad, pad_on_right, i, islong, islonglong;
	long long val = 0;
	int res = 0, length = 0;

	while ((c = *fmt++) != '\0') {
		if (c == '%') {
			c = *fmt++;
			left_prec = right_prec = pad_on_right = islong = islonglong = 0;
			if (c == '-') {
				c = *fmt++;
				pad_on_right++;
			}
			if (c == '0') {
				zero_fill = true;
				c = *fmt++;
			} else {
				zero_fill = false;
			}
			while (is_digit(c)) {
				left_prec = (left_prec * 10) + (c - '0');
				c = *fmt++;
			}
			if (c == '.') {
				c = *fmt++;
				zero_fill++;
				while (is_digit(c)) {
					right_prec = (right_prec * 10) + (c - '0');
					c = *fmt++;
				}
			} else {
				right_prec = left_prec;
			}
			sign = '\0';
			if (c == 'l') {
				// 'long' qualifier
				c = *fmt++;
				islong = 1;
				if (c == 'l') {
					// long long qualifier
					c = *fmt++;
					islonglong = 1;
				}
			}
			if (c == 'z') {
				c = *fmt++;
				islong = sizeof(unsigned int) == sizeof(long);
			}
			// Fetch value [numeric descriptors only]
			switch (c) {
			case 'p':
				islong = 1;
			case 'd':
			case 'D':
			case 'x':
			case 'X':
			case 'u':
			case 'U':
			case 'b':
			case 'B':
				if (islonglong) {
					val = va_arg(ap, long long);
				} else if (islong) {
					val = (long long)va_arg(ap, long);
				} else {
					val = (long long)va_arg(ap, int);
				}
				if ((c == 'd') || (c == 'D')) {
					if (val < 0) {
						sign = '-';
						val = -val;
					}
				} else {
					// Mask to unsigned, sized quantity
					if (islong) {
						val &= ((long long)1 << (sizeof(long) * 8)) - 1;
					} else if (!islonglong) {	// no need to mask longlong
						val &= ((long long)1 << (sizeof(int) * 8)) - 1;
					}
				}
				break;
			default:
				break;
			}
			// Process output
			switch (c) {
			case 'p':	// Pointer
				(*putc)('0', param);
				(*putc)('x', param);
				zero_fill = true;
				left_prec = sizeof(unsigned long) * 2;
				res += 2;	// Account for "0x" leadin
			case 'd':
			case 'D':
			case 'u':
			case 'U':
			case 'x':
			case 'X':
				switch (c) {
				case 'd':
				case 'D':
				case 'u':
				case 'U':
					length = _cvt(val, buf, 10, (char *)"0123456789");
					break;
				case 'p':
				case 'x':
					length = _cvt(val, buf, 16, (char *)"0123456789abcdef");
					break;
				case 'X':
					length = _cvt(val, buf, 16, (char *)"0123456789ABCDEF");
					break;
				}
				cp = buf;
				break;
			case 's':
			case 'S':
				cp = va_arg(ap, char *);
				if (cp == NULL)
					cp = (char *)"<null>";
				length = 0;
				while (cp[length] != '\0')
					length++;
				break;
			case 'c':
			case 'C':
				c = va_arg(ap, int /*char */ );
				(*putc)(c, param);
				res++;
				continue;
			case 'b':
			case 'B':
				length = left_prec;
				if (left_prec == 0) {
					if (islonglong)
						length = sizeof(long long) * 8;
					else if (islong)
						length = sizeof(long) * 8;
					else
						length = sizeof(int) * 8;
				}
				for (i = 0; i < length - 1; i++) {
					buf[i] = ((val & ((long long)1 << i)) ? '1' : '.');
				}
				cp = buf;
				break;
			case '%':
				(*putc)('%', param);
				res++;
				continue;
			default:
				(*putc)('%', param);
				(*putc)(c, param);
				res += 2;
				continue;
			}
			pad = left_prec - length;
			if (sign != '\0') {
				pad--;
			}
			if (zero_fill) {
				c = '0';
				if (sign != '\0') {
					(*putc)(sign, param);
					res++;
					sign = '\0';
				}
			} else {
				c = ' ';
			}
			if (!pad_on_right) {
				while (pad-- > 0) {
					(*putc)(c, param);
					res++;
				}
			}
			if (sign != '\0') {
				(*putc)(sign, param);
				res++;
			}
			while (length-- > 0) {
				c = *cp++;
				(*putc)(c, param);
				res++;
			}
			if (pad_on_right) {
				while (pad-- > 0) {
					(*putc)(' ', param);
					res++;
				}
			}
		} else {
			(*putc)(c, param);
			res++;
		}
	}
	return (res);
}

struct _sputc_info {
	char *ptr;
	int max, len;
};

static void _sputc(char c, void **param)
{
	struct _sputc_info *info = (struct _sputc_info *)param;

	if (info->len < info->max) {
		*(info->ptr)++ = c;
		*(info->ptr) = '\0';
		info->len++;
	}
}

int SprintF(char *buf, const char *fmt, ...)
{
	int ret;
	va_list ap;
	struct _sputc_info info;

	va_start(ap, fmt);
	info.ptr = buf;
	info.max = INT_MAX;	// Unlimited
	info.len = 0;
	ret = _vprintf(_sputc, (void **)&info, fmt, ap);
	va_end(ap);
	return (info.len);
}

int dprintf(const char *fmt, ...)
{
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = _vprintf(_putc, (void **)0, fmt, ap);
	va_end(ap);
	return (ret);
}

int dvprintf(const char *fmt, va_list ap)
{
	return _vprintf(_putc, (void **)0, fmt, ap);
}

static void diag_vdump_buf_with_offset(__printf_fun *pf, u_char *p, u_int s, u_char *base)
{
	int i, c;

	if ((u_int)s > (u_int)p)
		s = (u_int)s - (u_int)p;

	while ((int)s > 0) {
		if (base)
			(*pf)("%08x: ", (u_int)p - (u_int)base);
		else
			(*pf)("%08x: ", p);

		for (i = 0; i < 16; i++) {
			if (i < (int)s)
				(*pf)("%02x ", p[i] & 0xFF);
			else
				(*pf)("   ");

			if (i == 7)
				(*pf)(" ");
		}
		(*pf)(" |");
		for (i = 0; i < 16; i++) {
			if (i < (int)s) {
				c = p[i] & 0xFF;
				if ((c < 0x20) || (c >= 0x7F))
					c = '.';
			} else
				c = ' ';

			(*pf)("%c", c);
		}
		(*pf)("|\n");
		s -= 16;
		p += 16;
	}
}

void ddump(u_char *p, u_int s)
{
	diag_vdump_buf_with_offset(dprintf, p, s, 0);
}

#if defined(CONFIG_NOR_TEST)
unsigned int rand2(void)
{
	static unsigned int x = 123456789;
	static unsigned int y = 362436;
	static unsigned int z = 521288629;
	static unsigned int c = 7654321;
	unsigned long long t, a = 698769069;

	x = 69069 * x + 12345;
	y ^= (y << 13);
	y ^= (y >> 17);
	y ^= (y << 5);
	t = a * z + c;
	c = (t >> 32);
	z = t;

	return x + y + z;
}
#endif

void twiddle(void)
{
	static int twiddle_count;

	Putchar("-\\|/"[(twiddle_count++) & 3]);
	Putchar('\b');
}

void delay_ms(unsigned int time_ms)
{
	unsigned int preTime;

	preTime = get_timer_jiffies();
	while (get_timer_jiffies() - preTime < time_ms / 10) ;
}

void delay_sec(unsigned int time_sec)
{
	delay_ms(time_sec * 1000);
}

int printScale(char *buf, unsigned int int_part)
{
	unsigned int i;
	const char *unit = "B\0K\0M\0G\0T";

	for (i = 0; i < 4; i++) {
		if (int_part >= 1024) {
			int_part >>= 10;
			unit += 2;	/* K, M, G, T */
		}
	}
	return SprintF(buf, "%u%s", int_part, unit);
}
