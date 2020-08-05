#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "instrument.h"
#include "cmd.h"

int main(int argc, char **argv)
{
	select_event_loop();
	return 0;
}
