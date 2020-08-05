#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdint.h>

#define RBUFSZBIT 10
#define HISTSIZ ((1 << 5) - 1)
#define RBUFSIZ	((1 << RBUFSZBIT) - 1)
#define NULL_MASK_1 0x01010101L
#define NULL_MASK_2 0x80808080L
#define ROUNDUP(X) (((X) + 3) & ~3)

// Nonzero if any byte of X contains a NULL.
#define STR_DETECTNULL(X) \
    (((X) - (uint32_t)NULL_MASK_1) & \
     ~(X) & (uint32_t)NULL_MASK_2)

struct apmib_set_hist {
	int top, bottom;
	int values[HISTSIZ + 1];
	int head, tail, forehead;
	char buffer[RBUFSIZ + 1];
};

int apmib_set_hist_is_string(int id)
{
	return (id < (1 << RBUFSZBIT)) ? 1 : 0;
}

int apmib_set_hist_real_id(int id)
{
	return (apmib_set_hist_is_string(id)) ? 0 : (id >> RBUFSZBIT);
}

static struct apmib_set_hist* apmib_set_hist_state(void)
{
	static struct apmib_set_hist ash;
	return &ash;
}

static size_t apmib_set_hist_strlen(int i, struct apmib_set_hist *ash)
{
	int len;
	for (len = 0; !STR_DETECTNULL(*((uint32_t *)&ash->buffer[i])); i = (i + 4) & RBUFSIZ)
		len += 4;
	for (; ash->buffer[i]; i = (i + 1) & RBUFSIZ)
		len++;
	return len;
}

static int apmib_set_hist_strcmp(char *s, int i, struct apmib_set_hist *ash)
{
	int c1, c2;

	while (1) {
		c1 = *s++;
		c2 = ash->buffer[i];
		i = (i + 1) & RBUFSIZ;
		if (c1 != c2)
			return c1 < c2 ? -1 : 1;
		if (!c1)
			break;
	}
	return 0;
}

static int apmib_set_hist_pile(int value)
{
	struct apmib_set_hist *ash = apmib_set_hist_state();
	ash->top = (ash->top + 1) & HISTSIZ;
	if (ash->top == ash->bottom)
		ash->bottom = (ash->bottom + 1) & HISTSIZ;
	ash->values[ash->top] = value;
	return 0;
}

/*
  The id should be less than 2^(32 - RBUFSZBIT)
*/
int apmib_set_hist_put(int id)
{
	uint32_t value = (uint32_t)id;
	if (!value || ((value << RBUFSZBIT) >> RBUFSZBIT) != value)
		return -1;
	return apmib_set_hist_pile(id << RBUFSZBIT);
}

int apmib_set_hist_string_put(const char *name)
{
	struct apmib_set_hist *ash = apmib_set_hist_state();
	int spc = RBUFSIZ, c, i, len = name ? strlen(name) + 1 : 0;

	if (len <= 1)
		return -1;
	if (ash->head > ash->tail)
		spc = RBUFSIZ - (ash->head - ash->tail);
	else if (ash->head < ash->tail)
		spc = ash->tail - ash->head;
	len = ROUNDUP(len);
	if (len > spc || ((ash->head + len) & RBUFSIZ) == ash->tail)
		return -1;

	for (i = ash->head; (c = *name++); i = (i + 1) & RBUFSIZ, len--)
		ash->buffer[i] = c;
	while (len-- > 0) {
		ash->buffer[i] = '\0';
		i = (i + 1) & RBUFSIZ;
	}
	ash->forehead = ash->head;
	ash->head = i;

	return apmib_set_hist_pile(ash->forehead);
}

static int apmib_set_hist_values(int inc, int top)
{
	struct apmib_set_hist *ash = apmib_set_hist_state();
	int i, id, len, single;

	if (inc && top)
		return -1;
	if (ash->top == ash->bottom)
		return -1;
	if (top)
		i = ash->top;
	else
		i = (ash->bottom + 1) & HISTSIZ;
	id = ash->values[i];
	if (inc) {
		if ((uint32_t)id < (1 << RBUFSZBIT)) {
			len = apmib_set_hist_strlen(id, ash);
			single = (ash->tail == ash->forehead);
			ash->tail = ROUNDUP(ash->tail + len + 1);
			if (single)
				ash->forehead = ash->tail;
		}
		ash->bottom = i;
	}
	return id;
}

int apmib_set_hist_get(void)
{
	return apmib_set_hist_values(1, 0);
}

void apmib_set_hist_clear(void)
{
	struct apmib_set_hist *ash = apmib_set_hist_state();
	ash->top = ash->bottom = 0;
	ash->forehead = ash->tail = ash->head;
}

int apmib_set_hist_peek(void)
{
	return apmib_set_hist_values(0, 0);
}

int apmib_set_hist_peek_last(void)
{
	return apmib_set_hist_values(0, 1);
}

int apmib_set_hist_search(int id)
{
	struct apmib_set_hist *ash;
	uint32_t value = (uint32_t)id;
	int i;

	if (!value || ((value << RBUFSZBIT) >> RBUFSZBIT) != value)
		return -1;

	ash = apmib_set_hist_state();
	for (i = ash->bottom; i != ash->top; ) {
		i = (i + 1) & HISTSIZ;
		if (ash->values[i] == (id << RBUFSZBIT))
			return i;
	}
	return -1;
}

int apmib_set_hist_search_any(int id, ...)
{
	va_list args;

	va_start(args, id);
	while (id) {
		if (apmib_set_hist_search(id) > -1)
			return 1;
		id = va_arg(args, int);
	}
	va_end(args);
	return 0;
}

int apmib_set_hist_strstr(char *name)
{
	struct apmib_set_hist *ash = apmib_set_hist_state();
	int i;

	for (i = ash->bottom; i != ash->top; ) {
		i = (i + 1) & HISTSIZ;
		if (ash->values[i] < (1 << RBUFSZBIT) &&
		    !apmib_set_hist_strcmp(name, ash->values[i], ash))
			return i;
	}
	return -1;
}

#ifdef ASH_STRINGIFY
static char *apmib_set_hist_strcpy(char *dst, int i, struct apmib_set_hist *ash)
{
	char *saved = dst;
	while (!STR_DETECTNULL(*((uint32_t *)&ash->buffer[i]))) {
		*(uint32_t *)dst = *((uint32_t *)&ash->buffer[i]);
		dst += 4;
		i = (i + 4) & RBUFSIZ;
	}
	for (; ash->buffer[i]; i = (i + 1) & RBUFSIZ)
		*dst++ = ash->buffer[i];
	*dst = '\0';
	return saved;
}

char *apmib_set_hist_stringify(int i)
{
	static char *p = NULL;
	static char buf[64];
	char *q = NULL;
	struct apmib_set_hist *ash = apmib_set_hist_state();
	int len;

	len = apmib_set_hist_strlen(i, ash);
	if ((len + 1) <= sizeof(buf))
		q = apmib_set_hist_strcpy(buf, i, ash);
	else if ((q = realloc(p, len + 1)))
		p = apmib_set_hist_strcpy(q, i, ash);

	return q;
}
#endif
