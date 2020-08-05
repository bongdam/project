#ifndef __STREAM_FRAG_H
#define __STREAM_FRAG_H

#include <linux_list.h>

#define MIN_FRAG_SIZE 8192
#define MAX_MONOLITHIC_SIZE (MIN_FRAG_SIZE * 8)

struct stream_fragment {
	struct list_head list;
	int data, tail, size;
	char buf[0];
};

struct stream_fragment_iterator {
	struct list_head *head;
	struct list_head *last;
	int from;
};

static inline int stream_frag_min(int a, int b)
{
	return (a < b) ? a : b;
}

static inline int stream_frag_pended(struct stream_fragment *p)
{
	return p->tail - p->data;
}

static inline int stream_frag_headroom(struct stream_fragment *p)
{
	return p->data;
}

static inline int stream_frag_availroom(struct stream_fragment *p)
{
	return p->size - p->tail;
}

static inline void stream_frag_reserve(struct stream_fragment *p, int len)
{
	if ((p->tail + len) <= p->size) {
		if ((p->tail - p->data) > 0)
			memmove(p->buf + p->data + len,
				p->buf + p->data, (p->tail - p->data));
		p->data += len;
		p->tail += len;
	}
}

static inline struct stream_fragment *stream_frag_first(struct list_head *h)
{
	return list_empty(h) ? NULL : \
		list_entry(h->next, struct stream_fragment, list);
}

static inline struct stream_fragment *stream_frag_end(struct list_head *h)
{
	return list_empty(h) ? NULL : \
		list_entry(h->prev, struct stream_fragment, list);
}

static inline int stream_frag_empty(struct list_head *h)
{
	struct stream_fragment *p = stream_frag_first(h);
	return (!p || !stream_frag_pended(p));
}

#ifdef __cplusplus
extern "C" {
#endif

ssize_t stream_frag_printf(struct list_head *h, const char *fmt, ...);
ssize_t stream_frag_write(struct list_head *h, void *buf, size_t count);
ssize_t stream_frag_write_monolithic(struct list_head *h, void *buf, size_t count);
void stream_frag_init_iterator(struct list_head *h, struct stream_fragment_iterator *it);
ssize_t stream_frag_gets(struct stream_fragment_iterator *it, void *buf, int count);
void stream_frag_freeall(struct list_head *h);

#ifdef __cplusplus
}
#endif
#endif
