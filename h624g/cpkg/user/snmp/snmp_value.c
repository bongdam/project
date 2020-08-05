#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include "bcmnvram.h"
#include "apmib_defs.h"
#include "apmib.h"
#include "snmp_main.h"

char * getValue(char *name)
{
	return (nvram_get(name));
}

int setValue(char *name, char *value)
{
	if(name == NULL)
		return -1;
	else
		return (nvram_set(name, value));
}

int unsetValue(char *name)
{
	return (nvram_unset(name));
}

int setValue_mib(int id, void *value)
{
	return (apmib_set(id, value));
}

int getValue_mib(int id, void *value )
{
	return (apmib_get(id, value));
}

void commitValue()
{
	nvram_commit();
}
