#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/module.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/rbtree.h>
#include <linux/mutex.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/ioctl.h>
#include "bcmnvram.h"

struct nvram_tuple {
	struct rb_node link;
	char *name;
	char *value;
	char buf[0];
};

static DEFINE_MUTEX(nvram_lock);
static struct rb_root _nvram_root;
static int nvram_major = -1;
static struct class *nvram_class = NULL;

static struct nvram_tuple *
_nvram_update_value(struct nvram_tuple *t, const char *value)
{
	if (!t->value || ((strlen(t->value) < strlen(value)) && ({ kfree(t->value); 1; })))
		t->value = kstrdup(value, GFP_KERNEL);
	else if (strcmp(t->value, value))
		strcpy(t->value, value);
	return t;
}

static struct nvram_tuple *
_nvram_insert(const char *name, const char *value, struct rb_root *root)
{
	struct rb_node **new = &(root->rb_node), *parent = NULL;
	struct nvram_tuple *t;
	int res;

	while (*new) {
		t = rb_entry(*new, struct nvram_tuple, link);
		res = strcmp(name, t->name);
		parent = *new;
		if (res < 0)
			new = &((*new)->rb_left);
		else if (res > 0)
			new = &((*new)->rb_right);
		else
			return _nvram_update_value(t, value);
	}

	t = (struct nvram_tuple *)kmalloc(sizeof(*t) + strlen(name) + 1, GFP_KERNEL);
	if (likely(t)) {
		t->name = strcpy(t->buf, name);
		t->value = kstrdup(value, GFP_KERNEL);
		rb_link_node(&t->link, parent, new);
		rb_insert_color(&t->link, root);
	}
	return t;
}

static struct nvram_tuple *_nvram_delete(const char *name, struct rb_root *root)
{
	struct rb_node **new = &(root->rb_node), *parent = NULL;

	while (*new) {
		struct nvram_tuple *t = rb_entry(*new, struct nvram_tuple, link);
		int res = strcmp(name, t->name);
		parent = *new;
		if (res < 0)
			new = &((*new)->rb_left);
		else if (res > 0)
			new = &((*new)->rb_right);
		else {
			rb_erase(&t->link, root);
			kfree(t->value);
			kfree(t);
			return t;
		}
	}
	return NULL;
}

static struct nvram_tuple *_nvram_search(const char *name, struct rb_root *root)
{
	struct rb_node **new = &(root->rb_node), *parent = NULL;

	while (*new) {
		struct nvram_tuple *t = rb_entry(*new, struct nvram_tuple, link);
		int res = strcmp(name, t->name);
		parent = *new;
		if (res < 0)
			new = &((*new)->rb_left);
		else if (res > 0)
			new = &((*new)->rb_right);
		else
			return t;
	}
	return NULL;
}

static int _nvram_getall(char *buf, size_t len, struct rb_root *root)
{
	struct rb_node *rbp;
	size_t count = 0;
	int n, ret = 0;

	/* for the latter terminating NULL of "\0\0" */
	len -= 1;
	for (rbp = rb_first(root); rbp; rbp = rb_next(rbp)) {
		struct nvram_tuple *t = rb_entry(rbp, struct nvram_tuple, link);
		n = snprintf(buf + count, len - count, "%s=%s", t->name, t->value);
		ret += n + 1;
		if (n >= (len - count))
			buf[count] = '\0';
		else
			count += n + 1;
	}

	buf[count++] = '\0';
	if (len > count)
		memset(buf + count, 0xff, len - count + 1);
	return ret + 1;
}

static void _nvram_freeall(struct rb_root *root)
{
	struct rb_node *rbp;

	while ((rbp = rb_first(root))) {
		struct nvram_tuple *t = rb_entry(rbp, struct nvram_tuple, link);
		rb_erase(rbp, root);
		kfree(t->value);
		kfree(t);
	}
}

static long dev_nvram_get(char __user *buf, size_t count)
{
	char tmp[100], *name = tmp;
	long len, ret, cplen;

	len = buf ? strnlen_user(buf, PAGE_SIZE) : 0;
	if (!len || len > PAGE_SIZE)
		return -EINVAL;
	else if (len > sizeof(tmp) && !(name = kmalloc(len, GFP_KERNEL)))
		return -ENOMEM;

	ret = strncpy_from_user(name, buf, len);
	if (ret < 0)
		goto done;

	mutex_lock(&nvram_lock);
	if (*name == '\0') {
		if (!(name = kmalloc(count, GFP_KERNEL)))
			ret = -ENOMEM;
		else {
			/* Get all variables */
			ret = _nvram_getall(name, count, &_nvram_root);
			if (copy_to_user(buf, name, (count < ret) ? count : ret))
				ret = -EFAULT;
		}
	} else {
		struct nvram_tuple *t = _nvram_search(name, &_nvram_root);
		if (t && t->value) {
			ret = strlen(t->value);
			cplen = (count < (ret + 1)) ? count - 1 : ret;
			if (copy_to_user(buf, t->value, cplen) ||
			    (({ buf += cplen; 1; }) && put_user((char)'\0', buf)))
				ret = -EFAULT;
		} else
			ret = -ENOENT;
	}
	mutex_unlock(&nvram_lock);

done:
	if (name != tmp)
		kfree(name);

	return ret;
}

static long dev_nvram_set(char __user *buf, size_t count)
{
	char tmp[256], *name = tmp, *value;
	long ret, len;

	len = buf ? strnlen_user(buf, NVRAM_SPACE - 2) : 0;
	if (!len || len > (NVRAM_SPACE - 2))
		return -EINVAL;
	else if (len > sizeof(tmp) && !(name = kmalloc(len, GFP_KERNEL)))
		return -ENOMEM;

	ret = strncpy_from_user(name, buf, len);
	if (ret < 0)
		goto done;

	value = name;
	name = strsep(&value, "=");

	mutex_lock(&nvram_lock);
	if (strlen(name) > (PAGE_SIZE - 1))
		ret = -EINVAL;
	else if (value)
		ret = _nvram_insert(name, value, &_nvram_root) ? 0 : -ENOMEM;
	else if (!_nvram_delete(name, &_nvram_root))
		ret = -ENOENT;
	else
		ret = 0;
	mutex_unlock(&nvram_lock);
done:
	if (name != tmp)
		kfree(name);

	return ret;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
static int
#else
static long
#endif
dev_nvram_ioctl(
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
        struct inode *inode,
#endif
        struct file *file,
        unsigned int cmd,
        unsigned long arg)
{
	struct nvreq req;
	int ret;

	if (_IOC_TYPE(cmd) != NVRAM_IOTYPE)
		return -EINVAL;

	switch (_IOC_NR(cmd)) {
	case __NVRAM_CMD_GET:
		if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
			return -EFAULT;
		if (req.length <= 0)
			return -EINVAL;
		ret = dev_nvram_get(req.sptr, req.length);
		return (ret > -1) ?
		       put_user(ret, (int __user *)&((struct nvreq *)arg)->length) : ret;

	case __NVRAM_CMD_SET:
		if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
			return -EFAULT;
		return dev_nvram_set(req.sptr, req.length);

	default:
		return -EINVAL;
	}
}

static struct file_operations dev_nvram_fops;
static void __exit dev_nvram_exit(void)
{
	if (nvram_class) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
		class_device_destroy(nvram_class, MKDEV(nvram_major, 0));
#else /* 2.6.36 and up */
		device_destroy(nvram_class, MKDEV(nvram_major, 0));
#endif
		class_destroy(nvram_class);
	}

	if (nvram_major >= 0)
		unregister_chrdev(nvram_major, "nvram");

	mutex_lock(&nvram_lock);

	_nvram_freeall(&_nvram_root);

	mutex_unlock(&nvram_lock);
}

static int __init dev_nvram_init(void)
{
	memset(&dev_nvram_fops, 0, sizeof(dev_nvram_fops));

	dev_nvram_fops.owner = THIS_MODULE;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
	dev_nvram_fops.ioctl = dev_nvram_ioctl;
#else
	dev_nvram_fops.unlocked_ioctl =	dev_nvram_ioctl;
#endif
	/* Register char device */
	if ((nvram_major = register_chrdev(0, "nvram", &dev_nvram_fops)) < 0)
		return nvram_major;

	/* Create /dev/nvram handle */
	nvram_class = class_create(THIS_MODULE, "nvram");
	if (IS_ERR(nvram_class)) {
		unregister_chrdev(nvram_major, "nvram");
		printk("Error creating nvram class\n");
		return PTR_ERR(nvram_class);
	}

	/* Add the device nvram0 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
	class_device_create(nvram_class, NULL, MKDEV(nvram_major, 0), NULL, "nvram");
#else /* Linux 2.6.36 and above */
	device_create(nvram_class, NULL, MKDEV(nvram_major, 0), NULL, "nvram");
#endif	/* Linux 2.6.36 */
	return 0;
}

module_init(dev_nvram_init);
module_exit(dev_nvram_exit);
