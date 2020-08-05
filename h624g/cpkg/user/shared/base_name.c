#include <string.h>

const char *base_name(const char *name)
{
	const char *cp = strrchr(name, '/');
	if (cp)
		return cp + 1;
	return name;
}
