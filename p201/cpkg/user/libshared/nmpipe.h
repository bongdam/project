#ifndef _nmpipe_h_
#define _nmpipe_h_

struct nmpipe;
ssize_t presponse(struct nmpipe *p, void *vptr, size_t maxlen);
struct nmpipe *prequest(const char *cmd, const char *pathname);
int prelease(struct nmpipe *p);

#endif
