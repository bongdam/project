#ifndef __MAKE_UNIQCOOKIE_H__
#define __MAKE_UNIQCOOKIE_H__
#include <netinet/in.h>

int rand_cipherkey(void);

#define MAX_UIDLEN  80

struct cookie_session {
	unsigned jiffy;
	char uid[MAX_UIDLEN];
	char pwd[MAX_UIDLEN];
	struct in_addr host;
};

char *creat_cookie(const char *uid, const char *pwd, struct in_addr host, char *out, size_t outlen);
int parse_cookie(const char *cookie, struct cookie_session *cs);
char *b64_encode(unsigned char *src, int src_len, unsigned char *space, int space_len);
int b64_decode(const char *str, unsigned char *space, int size);
#endif
