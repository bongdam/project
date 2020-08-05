#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "rbtree.h"

struct nvram_rbnode {
	struct rb_node link;
	char *name, *value;
};

struct rb_root nvram_rbroot = {.rb_node = NULL };

static struct nvram_rbnode *nvram_mget(const char *name, char *value)
{
	struct nvram_rbnode *p;

	p = (struct nvram_rbnode *)malloc(sizeof(*p));
	if (!p)
		return NULL;
	p->name = strdup(name);
	if (!p->name)
		goto out2;
	p->value = strdup(value);
	if (!p->value)
		goto out1;
	return p;

 out1:
	free(p->name);
 out2:
	free(p);
	return NULL;
}

static int nvram_mput(struct nvram_rbnode *p)
{
	if (!p)
		return -1;
	if (p->name)
		free(p->name);
	if (p->value)
		free(p->value);
	free(p);
	return 0;
}

char *nvram_user_get(const char *name, char *value)
{
	struct rb_node **p = &(nvram_rbroot.rb_node);
	struct rb_node *parent = NULL;
	struct nvram_rbnode *entry;
	char *s;
	int res;

	while (*p) {
		parent = *p;
		entry = rb_entry(parent, struct nvram_rbnode, link);
		res = strcmp(name, entry->name);

		if (res < 0)
			p = &parent->rb_left;
		else if (res > 0)
			p = &parent->rb_right;
		else
			goto found;
	}

	if ((value == NULL) || (entry = nvram_mget(name, value)) == NULL)
		return value;

	rb_link_node(&entry->link, parent, p);
	rb_insert_color(&entry->link, &nvram_rbroot);
	return entry->value;

 found:
	if (value != NULL) {
		if (strcmp(entry->value, value)) {
			s = realloc(entry->value, strlen(value) + 1);
			if (!s)
				goto unset;
			strcpy(s, value);
			entry->value = s;
		}
		return entry->value;
	}

 unset:
	rb_erase(&entry->link, &nvram_rbroot);
	nvram_mput(entry);
	return value;
}
