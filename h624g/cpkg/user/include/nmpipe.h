#ifndef _nmpipe_h_
#define _nmpipe_h_

struct nmpipe {
	int fd;
	char path[64];
};

ssize_t presponse(struct nmpipe *p, void *vptr, size_t maxlen);
struct nmpipe *prequest(const char *cmd);
int prelease(struct nmpipe *p);

#endif
