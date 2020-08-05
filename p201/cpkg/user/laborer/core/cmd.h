#ifndef _cmd_h_
#define _cmd_h_

typedef struct fifo_command fifo_command;
struct fifo_command {
	fifo_command *next;
	const char *name;			// command itself
	const char *usage;			// usage guidance
	const char *helper;			// short helping description
	int (*hndl)(int, char **, int);		// handler
};

int fifo_cmd_register(const char *, const char *, const char *,
		int (*hndl)(int, char **, int));
int fifo_handle_line(char *cmd, char *response_pipe);

#endif
