#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/capability.h>
#include <linux/timex.h>
#include <asm/uaccess.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/proc_fs.h>
#include <linux/poll.h>
#include <linux/jiffies.h>
#include <linux/sched.h>
#include <dvflag.h>

#ifndef bool
#define bool    int
#endif

#ifndef true
#define true    1
#define false   0
#endif

typedef struct {
	struct list_head list;
	unsigned int caremask;
	atomic_t readable;
} dvflag_t;

static DEFINE_SPINLOCK(splock);
static LIST_HEAD(dvflag_head);
static unsigned int dvflag_bits;
static wait_queue_head_t dvflag_wq;
static int dvflag_ready = -1;

static unsigned int dvflag_set_common(unsigned int setbits,
				      unsigned int maskbits)
{
	unsigned int oldbits = dvflag_bits;
	unsigned long flags;
	dvflag_t *p;
	wait_queue_t *next, *curr;

	dvflag_bits &= ~maskbits;
	dvflag_bits |= (maskbits & setbits);

	if (unlikely(dvflag_ready < 0))
		return oldbits;

	spin_lock_irqsave(&splock, flags);
	list_for_each_entry(p, &dvflag_head, list) {
		if (p->caremask & maskbits)
			atomic_inc(&p->readable);
	}
	list_for_each_entry_safe(curr, next, &dvflag_wq.task_list, task_list) {
		struct poll_table_entry *entry = container_of(curr, struct poll_table_entry, wait);
		p = (dvflag_t *)entry->filp->private_data;
		if (p && (p->caremask & maskbits))
			curr->func(curr, TASK_INTERRUPTIBLE, 0, NULL);
	}
	spin_unlock_irqrestore(&splock, flags);

	return oldbits;
}

unsigned int dvflag_get(void)
{
	return dvflag_bits;
}
EXPORT_SYMBOL(dvflag_get);

unsigned int dvflag_set(unsigned int setbits, unsigned int mask)
{
	return dvflag_set_common(setbits, mask);
}
EXPORT_SYMBOL(dvflag_set);

static int dvflag_open(struct inode *inode, struct file *filp)
{
	unsigned long flags;
	dvflag_t *p;

	p = (dvflag_t *)kmalloc(sizeof(dvflag_t), GFP_KERNEL);
	if (p == 0)
		return -ENOMEM;
	p->caremask = 0xFFFFFFFF;
	atomic_set(&p->readable, 0);
	filp->private_data = (void *)p;
	spin_lock_irqsave(&splock, flags);
	list_add_tail(&p->list, &dvflag_head);
	spin_unlock_irqrestore(&splock, flags);
	return 0;
}

static int dvflag_release(struct inode *inode, struct file *filp)
{
	unsigned long flags;
	dvflag_t *p = (dvflag_t *)filp->private_data;

	spin_lock_irqsave(&splock, flags);
	filp->private_data = NULL;
	list_del(&p->list);
	spin_unlock_irqrestore(&splock, flags);
	kfree(p);
	return 0;
}

static ssize_t dvflag_read(struct file *filp, char __user *buf, size_t size,
			   loff_t *ppos)
{
	unsigned long flags;
	dvflag_t *p = (dvflag_t *)filp->private_data;

	if (size < sizeof(int))
		return -EINVAL;
	if (copy_to_user(buf, &dvflag_bits, sizeof(int)))
		return -EFAULT;

	spin_lock_irqsave(&splock, flags);
	//atomic_dec_if_positive(&p->readable);
	atomic_set(&p->readable, 0);
	spin_unlock_irqrestore(&splock, flags);
	return sizeof(int);
}

static ssize_t dvflag_write(struct file *filp, const char __user *buffer,
			    size_t count, loff_t *ppos)
{
	unsigned int kbuf[2];

	if (dvflag_ready < 0 || count != (sizeof(int) << 1))
		return -EINVAL;
	if (copy_from_user(kbuf, buffer, sizeof(int) << 1))
		return -EFAULT;
	dvflag_set_common(kbuf[0], kbuf[1]);
	return (sizeof(int) << 1);
}

static unsigned int dvflag_poll(struct file *file,
				struct poll_table_struct *wait)
{
	unsigned long flags;
	dvflag_t *p = (dvflag_t *)file->private_data;
	unsigned int mask = POLLOUT | POLLWRNORM;

	if (unlikely(dvflag_ready < 0))
		return 0;
	poll_wait(file, &dvflag_wq, wait);
	if (unlikely(dvflag_ready < 0))
		return 0;
	spin_lock_irqsave(&splock, flags);
	if (atomic_read(&p->readable) > 0)
		mask |= POLLIN | POLLRDNORM;
	spin_unlock_irqrestore(&splock, flags);
	return mask;
}

static long dvflag_ioctl(struct file *filp, unsigned int command, unsigned long arg)
{
	dvflag_t *p = (dvflag_t *)filp->private_data;
	unsigned int cmdnr = _IOC_NR(command);

	if (p == NULL)
		return -EINVAL;

	switch (cmdnr) {
	case DVFLGIO_SETMASK_INDEX:
		copy_from_user(&p->caremask, (unsigned int *)arg, sizeof(int));
		break;
	case DVFLGIO_GETMASK_INDEX:
		copy_to_user((unsigned int *)arg, &p->caremask, sizeof(int));
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

static struct file_operations proc_dvflag_operations = {
	.owner = THIS_MODULE,
	.open = dvflag_open,
	.read = dvflag_read,
	.write = dvflag_write,
	.poll = dvflag_poll,
	.unlocked_ioctl = dvflag_ioctl,
	.release = dvflag_release,
};

static int __init dvflag_init(void)
{
	init_waitqueue_head(&dvflag_wq);
	proc_create("dvflag", 0644, NULL, &proc_dvflag_operations);
	dvflag_ready = 0;
	return 0;
}

static void __exit dvflag_cleanup(void)
{
	dvflag_ready = -1;
	wake_up_interruptible_all(&dvflag_wq);
	remove_proc_entry("dvflag", NULL);
}

module_init(dvflag_init);
module_exit(dvflag_cleanup);
