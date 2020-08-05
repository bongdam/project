
#include <limits.h>

#define in_range(c, lo, up)  ((int)c >= lo && (int)c <= up)
#define isdigit(c)           in_range(c, '0', '9')
#define isxdigit(c)          (isdigit(c) || in_range(c, 'a', 'f') || in_range(c, 'A', 'F'))
#define islower(c)           in_range(c, 'a', 'z')
#define isspace(c) ((((c) == ' ') || (((unsigned int)((c) - 9)) <= (13 - 9))))


/* Works only for digits and letters, but small and fast */
#define TOLOWER(x) ((x) | 0x20)

static unsigned int guess_base(const char *cp)
{
	if (cp[0] == '0') {
		if (TOLOWER(cp[1]) == 'x' && isxdigit(cp[2]))
			return 16;
		else
			return 8;
	} else {
		return 10;
	}
}

/**
 * strtoul - convert a string to an unsigned long
 * @cp: The start of the string
 * @endp: A pointer to the end of the parsed string will be placed here
 * @base: The number base to use
 */
unsigned long strtoul(const char *cp, char **endp, unsigned int base)
{
	unsigned long result = 0;

	while (isspace(*cp))
		cp++;

	if (!base)
		base = guess_base(cp);

	if (base == 16 && cp[0] == '0' && TOLOWER(cp[1]) == 'x')
		cp += 2;

	while (isxdigit(*cp)) {
		unsigned int value;

		value = isdigit(*cp) ? *cp - '0' : TOLOWER(*cp) - 'a' + 10;
		if (value >= base)
			break;
		result = result * base + value;
		cp++;
	}

	if (endp)
		*endp = (char *)cp;
	return result;
}

/**
 * strtol - convert a string to a signed long
 * @cp: The start of the string
 * @endp: A pointer to the end of the parsed string will be placed here
 * @base: The number base to use
 */
long strtol(const char *cp, char **endp, unsigned int base)
{
	if (*cp == '-')
		return -strtoul(cp + 1, endp, base);
	return strtoul(cp, endp, base);
}
