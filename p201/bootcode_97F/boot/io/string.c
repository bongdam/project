/*
 *  linux/lib/string.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

/*
 * stupid library routines.. The optimized versions should generally be found
 * as inline code in <asm-xx/string.h>
 *
 * These are buggy as well..
 *
 * * Fri Jun 25 1999, Ingo Oeser <ioe@informatik.tu-chemnitz.de>
 * -  Added strsep() which will replace strtok() soon (because strsep() is
 *    reentrant and should be faster). Use only strsep() in new code, please.
 */

#include <linux/types.h>
#include <linux/string.h>

char *strcpy(char *dest, const char *src)
{
	char *tmp = dest;

	while ((*dest++ = *src++) != '\0')
		/* nothing */ ;
	return tmp;
}

int strncmp(const char *s1, const char *s2, size_t n)
{
	if (n == 0)
		return 0;

	while (n-- != 0 && *s1 == *s2) {
		if (n == 0 || *s1 == '\0' || *s2 == '\0')
			break;
		s1++;
		s2++;
	}
	return (*(unsigned char *)s1) - (*(unsigned char *)s2);
}

int strcmp(const char *cs, const char *ct)
{
	return strncmp(cs, ct, (size_t) - 1);
}

char *strchr(const char *s, int c)
{
	for (; *s != (char)c; ++s)
		if (*s == '\0')
			return NULL;
	return (char *)s;
}

size_t strlen(const char *s)
{
	const char *sc;

	for (sc = s; *sc != '\0'; ++sc)
		/* nothing */ ;
	return sc - s;
}

#define UNALIGNED1(X) \
     ((unsigned int)(X) & (sizeof(unsigned int) - 1))

#define UNALIGNED2(X, Y) \
     (((unsigned int)(X) & (sizeof(unsigned int) - 1)) | \
      ((unsigned int)(Y) & (sizeof(unsigned int) - 1)))

typedef union {
	unsigned char *s;	/* single-byte */
	unsigned int *q;	/* quad-byte */
} __uptr_t;

void *memset(void *s, int c, size_t n)
{
	__uptr_t p1 = {.s = (unsigned char *)s };
	int buffer;

	if (!UNALIGNED1(s)) {
		c &= 0xff;
		buffer = (c << 8) | c;
		buffer |= (buffer << 16);
		for (; n > 4; n -= 4)
			*p1.q++ = buffer;
	}
	while (n-- > 0)
		*p1.s++ = (char)c;
	return s;
}

void *memcpy(void *s1, const void *s2, size_t n)
{
	__uptr_t p1 = {.s = (unsigned char *)s1 };
	__uptr_t p2 = {.s = (unsigned char *)s2 };

	if (!UNALIGNED2(s1, s2)) {
		for (; n > 4; n -= 4)
			*p1.q++ = *p2.q++;
	}
	while (n-- > 0)
		*p1.s++ = *p2.s++;
	return s1;
}

int memcmp(const void *s1, const void *s2, size_t n)
{
	int res;
	__uptr_t p1 = {.s = (unsigned char *)s1 };
	__uptr_t p2 = {.s = (unsigned char *)s2 };

	if (!UNALIGNED2(s1, s2)) {
		for (; 4 < n; ++p1.q, ++p2.q, n -= 4) {
			if (*p1.q != *p2.q) {
				for (; 0 < n; ++p1.s, ++p2.s, n--)
					if ((res = *p1.s - *p2.s) != 0)
						return res;
				// NOT REACHED
			}
		}
	}
	for (; 0 < n; ++p1.s, ++p2.s, n--)
		if ((res = *p1.s - *p2.s) != 0)
			return res;
	return 0;
}

char *strstr(const char *s1, const char *s2)
{
	int l1, l2;

	l2 = strlen(s2);
	if (!l2)
		return (char *)s1;
	l1 = strlen(s1);
	while (l1 >= l2) {
		l1--;
		if (!memcmp(s1, s2, l2))
			return (char *)s1;
		s1++;
	}
	return NULL;
}
