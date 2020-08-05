#include <linux/module.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/uaccess.h>
#include <linux/proc_fs.h>
#include "os_util.h"

char *despaces(char *s)
{
	char *p, *q;
	int c;

	/* skip leading spaces */
	for (p = s; (c = *p) && (isspace(c) || iscntrl(c)); p++) ;
	/* run to the end of string */
	for (q = p; *q; c = *q++) ;
	for (q--; p < q && (isspace(c) || iscntrl(c)); c = *q)
		*q-- = '\0';
	if (p != s) {
		for (q = s; *p; *q++ = *p++) ;
		*q = 0;
	}
	return s;
}
EXPORT_SYMBOL(despaces);

int strargs(char *line, char *ag[], unsigned agsz, const char *delim)
{
	char *q, *p = line;
	unsigned i, ac = 0;

	while ((q = strsep(&p, delim))) {
		despaces(q);
		if (*q) {
			if (ac < agsz)
				ag[ac++] = q;
		}
	}
	for (i = ac; i < agsz; i++)
		ag[i] = NULL;
	return (int)ac;
}
EXPORT_SYMBOL(strargs);

size_t strtrim_from_user(char *dst, size_t dlen,
			const char __user *src, size_t count)
{
	int len;

	if (src == NULL || dst == NULL || dlen-- < 1)
		return 0;
	len = strncpy_from_user(dst, src, (long)((count > dlen) ? dlen : count));
	if (len > 0) {
		dst[len] = '\0';
		despaces(dst);
		return strlen(dst);
	}
	return 0;
}
EXPORT_SYMBOL(strtrim_from_user);

char *gets_from_user(char *dst, int size, const char __user **src, int *count)
{
	char *d = dst;
	const char __user *s = *src;
	int n, m = *count;
	char c;

	for (n = 1; n < size && m > 0; n++, m--) {
		get_user(c, s);
		*d = c;
		if (c == '\0')
			break;
		d++;
		s++;
		if (c == '\n')
			break;
	}
	*d = '\0';
	*count -= (int)(s - *src);
	*src = s;
	return (*dst) ? dst : NULL;
}
EXPORT_SYMBOL(gets_from_user);

int h_atoe(const char *s, unsigned char *addr)
{
	char tmp[32];
	char *q, *p = (char *)tmp;
	int i;

	if (!s || !addr)
		return -1;

	strncpy(tmp, s, sizeof(tmp) - 1);
	tmp[sizeof(tmp) - 1] = '\0';
	despaces(tmp);
	for (i = 0; (q = strsep(&p, ":-")); i++) {
		if (*q) {
			if (i < 6) {
				int n = (int)simple_strtol(q, &q, 16);
				if (!*q && n >= 0 && n < 256)
					*addr++ = (unsigned char)n;
				else
					break;
				continue;
			}
		}
		break;
	}

	return (i == 6) ? 0 : -1;
}
EXPORT_SYMBOL(h_atoe);

#ifdef CONFIG_PROC_FS
static int proc_read_thunk(struct seq_file *m, void *v)
{
	struct proc_dir_thunk *p = (struct proc_dir_thunk *)m->private;
	if (p->read_proc)
		return p->read_proc(m, p->data);
	return 0;
}

static ssize_t proc_write_thunk(struct file *file, const char __user *buffer,
				size_t count, loff_t *data)
{
	struct proc_dir_thunk *p = PDE_DATA(file_inode(file));
	if (p->write_proc)
		return p->write_proc(buffer, count, p->data);
	return count;
}

static int proc_open_thunk(struct inode *inode, struct file *file)
{
	return single_open(file, proc_read_thunk, PDE_DATA(inode));
}

static struct file_operations proc_thunk_fops = {
	.open = proc_open_thunk,
	.read = seq_read,
	.write = proc_write_thunk,
	.llseek = seq_lseek,
	.release = single_release,
};

int create_proc_thunk(const char *name, struct proc_dir_entry *parent,
		      struct proc_dir_thunk *thunk)
{
	return proc_create_data(name, 0644, parent,
		&proc_thunk_fops, (void *)thunk) ? 0 : -1;
}
EXPORT_SYMBOL(create_proc_thunk);
#endif

static DEFINE_SPINLOCK(in_addr_lock);

void in_addr_entry_add(struct in_addr_entry *addr, struct list_head *head)
{
	unsigned long flags;

	atomic_set(&addr->refcnt, 1);
	spin_lock_irqsave(&in_addr_lock, flags);
	list_add_tail_rcu(&addr->list, head);
	spin_unlock_irqrestore(&in_addr_lock, flags);
}
EXPORT_SYMBOL(in_addr_entry_add);

static struct in_addr_entry *__ip_addr_entry_get(struct list_head *head,
			int (*cmpr)(struct in_addr_entry *, void *), void *data)
{
	struct in_addr_entry *addr;

	list_for_each_entry_rcu(addr, head, list)
		if (!cmpr(addr, data))
			return addr;
	return NULL;
}

struct in_addr_entry *ip_addr_entry_get(struct list_head *head,
					int (*cmpr)(struct in_addr_entry *, void *),
					void *data)
{
	struct in_addr_entry *addr;
	rcu_read_lock();
	addr = __ip_addr_entry_get(head, cmpr, data);
	if (addr && !atomic_inc_not_zero(&addr->refcnt))
		addr = NULL;
	rcu_read_unlock();
	return addr;
}
EXPORT_SYMBOL(ip_addr_entry_get);

int ip_addr_entry_put(struct in_addr_entry *addr)
{
	unsigned long flags;
	if (atomic_dec_and_test(&addr->refcnt)) {
		spin_lock_irqsave(&in_addr_lock, flags);
		list_del_rcu(&addr->list);
		spin_unlock_irqrestore(&in_addr_lock, flags);
		synchronize_rcu();
		kfree(addr);
		return 0;
	}
	return -1;
}
EXPORT_SYMBOL(ip_addr_entry_put);

void ip_addr_entry_iterate(struct list_head *head,
			int (*visit)(struct in_addr_entry *, void *),
			void *data)
{
	struct in_addr_entry *addr;

	rcu_read_lock();
	list_for_each_entry_rcu(addr, head, list)
		if (visit(addr, data))
			break;
	rcu_read_unlock();
}
EXPORT_SYMBOL(ip_addr_entry_iterate);
