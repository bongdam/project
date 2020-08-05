#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <libytool.h>
#include "instrument.h"
#include "cmd.h"

/* ---- Private Function Prototypes -------------------------------------- */
/* ---- Private Variables ------------------------------------------------ */
static fifo_command *cmd_list = NULL;

/* ---- Public Variables ------------------------------------------------- */
/* ---- Extern variables and function prototype -------------------------- */
/* ---- Functions -------------------------------------------------------- */

static inline struct fifo_command *lookup_fifo_cmd(const char *name)
{
	struct fifo_command *c;
	for (c = cmd_list; c; c = c->next) {
		if (strcasecmp(c->name, name) == 0)
			return c;
	}
	return 0;
}

static int do_help(int ac, char **ag, char *response_pipe)
{
	fifo_command *c;

	if (ac <= 1) {
		for (c = cmd_list; c; c = c->next)
			fifo_reply(response_pipe, "  %-12s %s\n",
				c->name, (c->helper) ? c->helper : "");
	} else {
		for (c = cmd_list; c; c = c->next) {
			if (!strcmp(ag[1], c->name)) {
				fifo_reply(response_pipe, "%s\n",
					(c->usage) ? c->usage : "Not available");
				return 0;
			}
		}
		fifo_reply(response_pipe, "Unknown command, Type `help`\n");
	}
	return 0;
}

int fifo_cmd_register(const char *cmd_name,
		      const char *usage,
		      const char *helper, int (*hndl)(int, char **, char *))
{
	fifo_command *c;

	if (cmd_name == 0 || *cmd_name == 0 || hndl == 0)
		return -1;

	if (lookup_fifo_cmd(cmd_name)) {
		fprintf(stderr, "register_fifo_cmd: attempt to register synonyms\n");
		return -1;
	}

	c = (fifo_command *)malloc(sizeof(fifo_command));
	if (c) {
		c->name = cmd_name;
		c->usage = usage;
		c->helper = helper;
		c->hndl = hndl;
		c->next = cmd_list;
		cmd_list = c;
		return 0;
	}
	return -1;
}

int fifo_handle_line(char *cmd, char *response_pipe)
{
	fifo_command *c;
	int argc;
	char *args[24];

	argc = ystrargs(cmd, args, _countof(args), " \t\r\n", 0);
	if (argc > 0) {
		c = lookup_fifo_cmd(args[0]);
		if (c != NULL)
			return c->hndl(argc, args, response_pipe);
	}
	fifo_reply(response_pipe, "Unknown command, Type `help`\n");
	return 0;
}

static void __attribute__ ((constructor)) register_cmd_module(void)
{
	fifo_cmd_register("help", "help [<command>]",
			"display this help and exit", do_help);
}
