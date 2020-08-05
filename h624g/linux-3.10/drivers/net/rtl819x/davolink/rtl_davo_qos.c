#include <linux/module.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/ioport.h>
#include <linux/fcntl.h>
#include <linux/interrupt.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <asm/io.h>
#include <asm/uaccess.h>
#include <linux/delay.h>
#include <linux/wait.h>
#include <linux/proc_fs.h>
#include <linux/dvqos_ioctl.h>
#include <linux/mutex.h>
#include <linux/device.h>
	
#define DVKM_DV_QOS_DEV_MAJOR 		252
#define DVKM_DV_QOS_DEV_MAJOR_AUTO 	0

static int dvqos_open(struct inode *inode, struct file *file)
{
	return 0;
}

static int dvqos_close(struct inode *inode, struct file *file)
{
	return 0;
}

#define QOS_REGS_START 0xbb804700
#define QOS_REGS_LEN   516

static DEFINE_MUTEX(dvqos_chardev_mutex);

static long dvqos_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int ret = 0;
	
	mutex_lock(&dvqos_chardev_mutex);
	switch (cmd) {
	case DVQOS_OP_GETREGS:		
		if (copy_to_user((char *)arg, (char *)QOS_REGS_START, QOS_REGS_LEN))
			ret = -EFAULT;		
		break;
	case DVQOS_OP_READREG:
	case DVQOS_OP_WRITEREG:
		{
			struct qos_reg_t c;

#define QOS_REG_BASE 0xbb804700
			if (copy_from_user((char *)&c, (char *)arg, sizeof(c))) {
				ret = -EFAULT;
				break;
			}			
			if (cmd == DVQOS_OP_READREG) {
				c.val = *((unsigned int *)(QOS_REG_BASE + c.reg));
			} else {
				*((unsigned int *)(QOS_REG_BASE + c.reg)) = c.val;
				//printk("<1>qos:[%#x(offset:%#03x)] <- 0x%08x\n", (QOS_REG_BASE + c.reg), c.reg, c.val);
			}

			if (copy_to_user((char *)arg, (char *)&c, sizeof(c)))
				ret = -EFAULT;
		}
		break;
	default:
		break;
	}
	mutex_unlock(&dvqos_chardev_mutex);
	return ret;
}

struct file_operations dvqos_fops = {	
	.open			= dvqos_open,
	.release		= dvqos_close,
	.unlocked_ioctl	= dvqos_ioctl,
};

int dv_qos_init(void)
{
	register_chrdev(DVKM_DV_QOS_DEV_MAJOR, "dvqos", &dvqos_fops);
	return 1;
}

void dv_qos_exit(void)
{
	return;
}
