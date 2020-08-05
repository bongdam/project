#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include "instrument.h"

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

static int do_help(int ac, char **ag, int fd)
{
	fifo_command *c;

	if (ac <= 1) {
		for (c = cmd_list; c; c = c->next)
			dprintf(fd, "  %-12s %s\n",
				c->name, (c->helper) ? c->helper : "");
	} else {
		for (c = cmd_list; c; c = c->next) {
			if (!strcmp(ag[1], c->name)) {
				dprintf(fd, "%s\n",
					(c->usage) ? c->usage : "Not available");
				return 0;
			}
		}
		dprintf(fd, "Unknown command, Type `help`\n");
	}
	return 0;
}

int fifo_cmd_register(const char *cmd_name,
		      const char *usage,
		      const char *helper, int (*hndl)(int, char **, int))
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
	fifo_command *c = NULL;
	int argc;
	char *args[24];
	int fd = open_reply_pipe(response_pipe);

	if (fd < 0)
		return -1;
	argc = ystrargs(cmd, args, _countof(args), " \t\r\n", 0);
	if (argc > 0) {
		c = lookup_fifo_cmd(args[0]);
		if (c != NULL)
			c->hndl(argc, args, fd);
	}
	if (!c)
		fifo_reply(fd, "Unknown command, Type `help`\n");
	close(fd);
	return 0;
}

static int select_event_show(struct select_event_base *base, long fd)
{
	dprintf((int)fd, "%d %s\n", base->fd, base->name);
	return 1;
}

static int select_event_dump(int argc, char **argv, int fd)
{
	select_event_iterate((void *)select_event_show, (void *)(long)fd);
	return 0;
}

static void __attribute__ ((constructor)) register_cmd_module(void)
{
	fifo_cmd_register("help", "help [<command>]",
			"display this help and exit", do_help);
	fifo_cmd_register("show", NULL, NULL, select_event_dump);
}

static void __attribute__ ((destructor)) unregister_cmd_module(void)
{
	struct fifo_command *c, *next;
	for (c = cmd_list; c; c = next) {
		next = c->next;
		free(c);
	}
}

