#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include "stream_frag.h"

static struct stream_fragment *stream_frag_alloc(struct list_head *h, size_t size)
{
	struct stream_fragment *p;
	p = (struct stream_fragment *)malloc(sizeof(*p) + size);
	if (p != NULL) {
		p->data = p->tail = 0;
		p->size = size;
		list_add_tail(&p->list, h);
	}
	return p;
}

static struct stream_fragment *
stream_frag_expand(struct list_head *h, size_t size, struct stream_fragment *p)
{
	struct stream_fragment *n;
	struct list_head *prev;

	if (p == NULL)
		return stream_frag_alloc(h, size);
	prev = p->list.prev;
	list_del(&p->list);
	n = (struct stream_fragment *)realloc(p, sizeof(*p) + p->size + size);
	if (!n)
		n = p;
	else
		n->size += size;
	list_add(&n->list, prev);
	return n;
}

ssize_t stream_frag_printf(struct list_head *h, const char *fmt, ...)
{
	struct stream_fragment *p;
	va_list ap, aq;
	int n, extra_space;

	p = stream_frag_end(h);
	if (p == NULL && (p = stream_frag_alloc(h, MIN_FRAG_SIZE)) == NULL)
		return -1;

	extra_space = stream_frag_availroom(p);
	va_start(ap, fmt);
	va_copy(aq, ap);
	n = vsnprintf(p->buf + p->tail, extra_space, fmt, aq);
	va_end(aq);
	if (n >= extra_space) {
		p = stream_frag_alloc(h, ((n + 1) > MIN_FRAG_SIZE) ? n + 1 : MIN_FRAG_SIZE);
		n = p ? vsnprintf(p->buf, n + 1, fmt, ap) : -1;
	}
	if (n > 0)
		p->tail += n;
	va_end(ap);

	return n;
}

ssize_t stream_frag_write(struct list_head *h, void *buf, size_t count)
{
	struct stream_fragment *p = stream_frag_end(h);
	size_t n, cpynr;

	for (n = 0; n < count; n += cpynr) {
		if (p == NULL && (p = stream_frag_alloc(h, MIN_FRAG_SIZE)) == NULL)
			break;
		cpynr = stream_frag_min(stream_frag_availroom(p), count - n);
		memcpy(p->buf + p->tail, (char *)buf + n, cpynr);
		p->tail += cpynr;
		if (p->tail >= p->size)
			p = NULL;
	}
	return n;
}

ssize_t stream_frag_write_monolithic(struct list_head *h, void *buf, size_t count)
{
	struct stream_fragment *p = stream_frag_end(h);
	size_t n, cpynr;

	for (n = 0; n < count; n += cpynr) {
		if (p == NULL && (p = stream_frag_alloc(h, MIN_FRAG_SIZE)) == NULL)
			break;
		cpynr = stream_frag_min(stream_frag_availroom(p), count - n);
		memcpy(p->buf + p->tail, (char *)buf + n, cpynr);
		p->tail += cpynr;
		if (p->tail >= p->size) {
			if (p->tail >= MAX_MONOLITHIC_SIZE)
				p = NULL;
			else if (!(p = stream_frag_expand(h, MIN_FRAG_SIZE, p)))
				break;
		}
	}
	return n;
}

void stream_frag_init_iterator(struct list_head *h, struct stream_fragment_iterator *it)
{
	struct stream_fragment *p = stream_frag_first(h);
	it->from = (p) ? p->data : 0;
	it->head = h;
	it->last = h->next;
}

ssize_t stream_frag_gets(struct stream_fragment_iterator *it, void *buf, int count)
{
	struct stream_fragment *p;
	char *cp = (char *)buf;

	if (count-- <= 0)
		return 0;

	for (p = list_entry(it->last, struct stream_fragment, list);
	     &p->list != it->head;
	     p = list_entry(p->list.next, struct stream_fragment, list),
				it->from = p->data, it->last = &p->list) {
		while (count > 0 && it->from < p->tail) {
			char c = p->buf[it->from++];
			*cp++ = c;
			count--;
			if (c == '\n')
				goto out;
		}

		if (count <= 0)
			break;
	}
out:
	*cp = '\0';
	return (int)(cp - (char *)buf);
}

void stream_frag_freeall(struct list_head *h)
{
	struct stream_fragment *p;
	while ((p = stream_frag_first(h)) != NULL) {
		list_del(&p->list);
		free(p);
	}
}
