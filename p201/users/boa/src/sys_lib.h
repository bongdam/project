#ifndef _INCLUDE_SYSLIB_H
#define _INCLUDE_SYSLIB_H

typedef struct variable_s {
	char *nvram_name;
} variable;

int sys_decrypt(unsigned char *e, int elen, int dbufsz);
int sys_encrypt(unsigned char *d, int dlen, int ebufsz);
#endif
