#ifndef _os_util_h_
#define _os_util_h_

#ifdef __KERNEL__
#include <linux/kernel.h>
#include <linux/spinlock.h>
#include <asm/cmpxchg.h>
#include <linux/in.h>

#include <stdarg.h>

extern char *despaces(char *);
extern int strargs(char *, char *[], unsigned, const char *);
extern size_t strtrim_from_user(char *dst, size_t dlen, const char __user *src, size_t count);
extern int h_atoe(const char *s, unsigned char *addr);
extern char *gets_from_user(char *dst, int size, const char __user **src, int *count);

static inline void htonlp(__be32 *dest, __u32 *src, size_t n)
{
	while (n-- > 0) {
		register __u32 tmp = *src++;
		*dest++ = htonl(tmp);
	}
}

#ifdef __LITTLE_ENDIAN
#define cpu_to_be32pn(cpulong, n) htonlp(cpulong, cpulong, n)
#else
#define cpu_to_be32pn(cpulong, n) do {} while (0)
#endif

#define PF_DISCARD 0
#define PF_ACCEPT 1
#define PF_CONSUME 2

struct sk_buff;
struct pf_hook_ops {
	struct list_head list;
	int (*hook)(struct pf_hook_ops *, struct sk_buff *, void *);
	void *private_data;
	int priority;
};

int pf_register_hook(struct list_head *, struct pf_hook_ops *);
void pf_unregister_hook(struct pf_hook_ops *);

enum pf_hook_priorities {
	PFH_PRI_HIGHEST = INT_MIN,
	PFH_PRI_HIGH = -200,
	PFH_PRI_MIDDLE = 0,
	PFH_PRI_LOW = 200,
	PFH_PRI_LOWEST = INT_MAX,
	PFH_PRI_LAST = INT_MAX,
};

#ifdef CONFIG_PROC_FS
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

struct proc_dir_thunk {
	void *data;
	int (*read_proc)(struct seq_file *, void *);
	int (*write_proc)(const char __user *, size_t, void *);
};

extern int create_proc_thunk(const char *, struct proc_dir_entry *, struct proc_dir_thunk *);
#endif

static inline bool ether_addr_equal_u16(const u8 *addr1, const u16 addr2)
{
	return (*((const u16 *)addr1) ^ addr2) == 0;
}

static inline bool ether_addr_equal_2bytes(const u8 *addr1, const u8 *addr2)
{
	return (*((const u16 *)addr1) ^ *((const u16 *)addr2)) == 0;
}

static inline bool ether_addr_equal_3bytes(const u8 *addr1, const u8 *addr2)
{
	return ether_addr_equal_2bytes(addr1, addr2) && (addr1[2] == addr2[2]);
}
#endif	/* __KERNEL__ */

struct in_addr_entry {
	struct list_head list;
	atomic_t refcnt;
	struct in_addr addr;
};

void in_addr_entry_add(struct in_addr_entry *entry, struct list_head *head);
struct in_addr_entry *ip_addr_entry_get(struct list_head *head,
					int (*cmpr)(struct in_addr_entry *, void *),
					void *data);
int ip_addr_entry_put(struct in_addr_entry *entry);
void ip_addr_entry_iterate(struct list_head *head,
			int (*visit)(struct in_addr_entry *, void *),
			void *data);
#ifdef CONFIG_DLF_RATELIMIT
int dle_limit_entry_init(void);
int dlf_limit_entry_delete(const u8 *addr);
int dlf_limit_entry_update(const u8 *addr, const char *iface);
int dlf_limit_entry_multicast_update(__be32 group, const char *iface);
int dlf_limit_entry_multicast_delete(__be32 group);
void dlf_limit_entry_expiry(void);
#endif

/*
 * counting singly-linked list head
 */
struct cslink_head {
	void		*first;
	__u32		qlen;
	spinlock_t	lock;
};

#define CSLIST_INITIALIZER(head) {			\
	.first = NULL,					\
	.qlen = 0,					\
	.lock = __SPIN_LOCK_UNLOCKED((head).lock),	\
}

static __inline__ int __cslink_empty(struct cslink_head *head)
{
	return (head->first == NULL);
}

static __inline__ void __cslink_insert_head(struct cslink_head *head, void **elem)
{
	*elem = head->first;
	head->first = (void *)elem;
	head->qlen++;
}

static __inline__ void *__cslink_remove_head(struct cslink_head *head)
{
	void *elem = head->first;
	head->first = *(void **)elem;
	head->qlen--;
	return elem;
}

static __inline__ void cslink_insert_head(struct cslink_head *head, void **elem)
{
	unsigned long flags;

	spin_lock_irqsave(&head->lock, flags);
	__cslink_insert_head(head, elem);
	spin_unlock_irqrestore(&head->lock, flags);
}

static __inline__ void *cslink_remove_head(struct cslink_head *head)
{
	unsigned long flags;
	void *elem;

	spin_lock_irqsave(&head->lock, flags);
	elem = __cslink_empty(head) ? NULL : __cslink_remove_head(head);
	spin_unlock_irqrestore(&head->lock, flags);
	return elem;
}
#endif	/* _os_util_h_ */
