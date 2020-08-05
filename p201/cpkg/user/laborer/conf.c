#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bcmnvram.h>

int conf_opmode(void)
{
	static int opmode = -1;
	if (opmode < 0)
		opmode = nvram_get_int("OP_MODE", 0);
	return opmode;
}

int conf_autoconf_method(void)
{
	return 0;
}

const char *conf_ifwan(void)
{
	return (!conf_opmode()) ? "eth1" : "br0";
}
