/* files.h */
#ifndef _FILES_H
#define _FILES_H

struct config_keyword {
	char keyword[20];
	int (*handler)(char *line, void *var);
	void *var;
	char def[40];
};


int read_config(char *file);
void write_leases(void);
void read_leases(char *file);
#endif
