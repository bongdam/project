// DAVO modified
/*
 * NVRAM variable manipulation (Linux kernel half)
 *
 * Copyright (C) 2013, Broadcom Corporation. All Rights Reserved.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * $Id: nvram_linux.c,v 1.10 2010-09-17 04:51:19 $
 */

#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,36)
#include <linux/config.h>
#endif

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/interrupt.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/bootmem.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/mtd/mtd.h>
#include <linux/sched.h>
#include <linux/mm.h>

#include <typedefs.h>
#include <bcmendian.h>
#include <bcmnvram.h>
#include <bcmutils.h>

#include <bcmdefs.h>
#ifdef __RTK_EQUIVALENT__
#include <hndsoc.h>
#include <siutils.h>
#include <hndmips.h>
#include <hndsflash.h>
#endif

#define NVRAM_MAJOR_NR	253

int nvram_space = DEF_NVRAM_SPACE;

#ifdef __DAVO__
static int nvram_backup(char *, struct nvram_header *,
			u_int32_t, u_int32_t, size_t);
#endif
/* In BSS to minimize text size and page aligned so it can be mmap()-ed */
static char nvram_buf[MAX_NVRAM_SPACE] __attribute__((aligned(PAGE_SIZE)));
static bool nvram_inram = FALSE;

#ifndef	MAX_MTD_DEVICES
#define	MAX_MTD_DEVICES	32
#endif

#ifdef MODULE

#define early_nvram_get(name) nvram_get(name)
#define early_nvram_getall(buf, count)	nvram_getall(buf, count)

#else /* !MODULE */

static char *early_nvram_get(const char *name);
#define FLASH_MEM_MAP_ADDR 0xB0000000

#define KB * 1024
#define MB * 1024 * 1024

static int __init
early_nvram_init(void)
{
	struct nvram_header *header;
	uint32 off, lim;

#ifdef CONFIG_RTL_8197F
	extern struct mtd_info *nvram_mtd;
	size_t len;

	if (nvram_mtd == NULL)
		return -1;

	lim = 0x00200000;		/* Minimum flash size - 2MB */
	off = CONFIG_RTL_FLASH_SIZE;
	for (header = (struct nvram_header *)nvram_buf; off >= lim; off >>= 1) {
		nvram_mtd->_read(nvram_mtd, off - MAX_NVRAM_SPACE, sizeof(*header), &len, header);
		if (header->magic == NVRAM_MAGIC) {
			nvram_mtd->_read(nvram_mtd, off - MAX_NVRAM_SPACE + sizeof(*header),
				MAX_NVRAM_SPACE - sizeof(*header), &len, (u_char *)&header[1]);
			if (nvram_calc_crc(header) == (uint8)header->crc_ver_init)
				return 0;
		}
	}

	printk("early_nvram_init: NVRAM not found\n");
	memset(nvram_buf, 0, sizeof(nvram_buf));
	return -1;
#else
	int i;
	uint32 base;
	u32 *src, *dst;

	base = KSEG1ADDR(FLASH_MEM_MAP_ADDR);
	lim = 0x00200000;		/* Minimum flash size - 2MB */
	off = CONFIG_RTL_FLASH_SIZE;

	while (off >= lim) {
		/* Windowed flash access */
		header = (struct nvram_header *)KSEG1ADDR(base + off - MAX_NVRAM_SPACE);
		if (header->magic == NVRAM_MAGIC) {
			if (nvram_calc_crc(header) == (uint8)header->crc_ver_init)
				goto found;
		}
		off >>= 1;
	}

	/* Try embedded NVRAM at 4 KB and 1 KB as last resorts */
	header = (struct nvram_header *)KSEG1ADDR(base + 4 KB);
	if (header->magic == NVRAM_MAGIC)
		if (nvram_calc_crc(header) == (uint8)header->crc_ver_init) {
			goto found;
		}

	header = (struct nvram_header *)KSEG1ADDR(base + 1 KB);
	if (header->magic == NVRAM_MAGIC)
		if (nvram_calc_crc(header) == (uint8)header->crc_ver_init) {
			goto found;
		}

	printk("early_nvram_init: NVRAM not found\n");
	return -1;

found:
	src = (u32 *)header;
	dst = (u32 *)nvram_buf;
	for (i = 0; i < sizeof(struct nvram_header); i += 4)
		*dst++ = *src++;
	for (; i < header->len && i < MAX_NVRAM_SPACE; i += 4)
		*dst++ = *src++;

	return 0;
#endif
}

/* Early (before mm or mtd) read-only access to NVRAM */
static char *
early_nvram_get(const char *name)
{
	char *var, *value, *end, *eq;

	if (!name)
		return NULL;

	if (!nvram_buf[0])
		if (early_nvram_init() != 0) {
			printk("early_nvram_get: Failed reading nvram var %s\n", name);
			return NULL;
		}

	/* Look for name=value and return value */
	var = &nvram_buf[sizeof(struct nvram_header)];
	end = nvram_buf + sizeof(nvram_buf) - 2;
	end[0] = end[1] = '\0';
	for (; *var; var = value + strlen(value) + 1) {
		if (!(eq = strchr(var, '=')))
			break;
		value = eq + 1;
		if ((eq - var) == strlen(name) && strncmp(var, name, (eq - var)) == 0)
			return value;
	}

	return NULL;
}

static int
early_nvram_getall(char *buf, int count)
{
	char *var, *end;
	int len = 0;

	if (!nvram_buf[0])
		if (early_nvram_init() != 0) {
			printk("early_nvram_getall: Failed reading nvram var\n");
			return -1;
		}

	memset(buf, 0, count);

	/* Write name=value\0 ... \0\0 */
	var = &nvram_buf[sizeof(struct nvram_header)];
	end = nvram_buf + sizeof(nvram_buf) - 2;
	end[0] = end[1] = '\0';
	for (; *var; var += strlen(var) + 1) {
		if ((count - len) <= (strlen(var) + 1))
			break;
		len += sprintf(buf + len, "%s", var) + 1;
	}

	return 0;
}
#endif /* !MODULE */

extern char * _nvram_get(const char *name);
extern int _nvram_set(const char *name, const char *value);
extern int _nvram_unset(const char *name);
extern int _nvram_getall(char *buf, int count);
extern int _nvram_commit(struct nvram_header *header);
extern int _nvram_init(void);
extern void _nvram_exit(void);

/* Globals */
static DEFINE_SPINLOCK(nvram_lock);
static struct semaphore nvram_sem;
static unsigned long nvram_offset = 0;
static int nvram_major = -1;
static struct class *nvram_class = NULL;
#if defined(CONFIG_RTL_8197F) && !defined(CONFIG_BCMNVRAM_MODULE)
struct mtd_info *nvram_mtd = NULL;
EXPORT_SYMBOL(nvram_mtd);
#else
static struct mtd_info *nvram_mtd = NULL;
#endif

int
_nvram_read(char *buf)
{
	struct nvram_header *header = (struct nvram_header *) buf;
	size_t len;
	int offset = 0;

	if (nvram_mtd) {
		offset = nvram_mtd->size - nvram_space;
	}
	if (nvram_inram || !nvram_mtd ||
	    nvram_mtd->_read(nvram_mtd, offset, nvram_space, &len, buf) ||
	    len != nvram_space ||
	    header->magic != NVRAM_MAGIC) {
		/* Maybe we can recover some data from early initialization */
		if (nvram_inram)
			printk("Sourcing NVRAM from ram\n");
		memcpy(buf, nvram_buf, nvram_space);
	}

	return 0;
}

struct nvram_tuple *
_nvram_realloc(struct nvram_tuple *t, const char *name, const char *value)
{
	if ((nvram_offset + strlen(value) + 1) > nvram_space)
		return NULL;

	if (!t) {
		if (!(t = kmalloc(sizeof(struct nvram_tuple) + strlen(name) + 1, GFP_ATOMIC)))
			return NULL;

		/* Copy name */
		t->name = (char *) &t[1];
		strcpy(t->name, name);

		t->value = NULL;
	}

	/* Copy value */
	if (t->value == NULL || strlen(t->value) < strlen(value)) {
		/* Alloc value space */
		t->value = &nvram_buf[nvram_offset];
		strcpy(t->value, value);
		nvram_offset += strlen(value) + 1;
	} else if( 0 != strcmp(t->value, value)) {
		/* In place */
		strcpy(t->value, value);
	}

	return t;
}

void
_nvram_free(struct nvram_tuple *t)
{
	if (!t) {
		nvram_offset = 0;
		memset( nvram_buf, 0, sizeof(nvram_buf) );
	} else {
		kfree(t);
	}
}

int
nvram_init(void *unused)
{
	return 0;
}

int
nvram_set(const char *name, const char *value)
{
	unsigned long flags;
	int ret;
	struct nvram_header *header;

	spin_lock_irqsave(&nvram_lock, flags);
	if ((ret = _nvram_set(name, value))) {
		printk( KERN_INFO "nvram: consolidating space!\n");
		/* Consolidate space and try again */
		if ((header = kmalloc(nvram_space, GFP_ATOMIC))) {
			if (_nvram_commit(header) == 0)
				ret = _nvram_set(name, value);
			kfree(header);
		}
	}
	spin_unlock_irqrestore(&nvram_lock, flags);

	return ret;
}

char *
real_nvram_get(const char *name)
{
	unsigned long flags;
	char *value;

	spin_lock_irqsave(&nvram_lock, flags);
	value = _nvram_get(name);
	spin_unlock_irqrestore(&nvram_lock, flags);

	return value;
}

char *
nvram_get(const char *name)
{
	if (nvram_major >= 0)
		return real_nvram_get(name);
	else
		return early_nvram_get(name);
}

int
nvram_unset(const char *name)
{
	unsigned long flags;
	int ret;

	spin_lock_irqsave(&nvram_lock, flags);
	ret = _nvram_unset(name);
	spin_unlock_irqrestore(&nvram_lock, flags);

	return ret;
}

static void
erase_callback(struct erase_info *done)
{
	wait_queue_head_t *wait_q = (wait_queue_head_t *)done->priv;
	wake_up(wait_q);
}

int
nvram_commit(void)
{
	char *buf;
	size_t erasesize, len, magic_len;
	unsigned int i;
	int ret;
	struct nvram_header *header;
	unsigned long flags;
	u_int32_t offset;
	DECLARE_WAITQUEUE(wait, current);
	wait_queue_head_t wait_q;
	struct erase_info erase;
	u_int32_t magic_offset = 0; /* Offset for writing MAGIC # */
#ifdef __DAVO__
	u_int32_t off, tmp;
#endif
	if (!nvram_mtd) {
		printk(KERN_ERR "nvram_commit: NVRAM not found\n");
		return -ENODEV;
	}

	if (in_interrupt()) {
		printk(KERN_WARNING "nvram_commit: not committing in interrupt\n");
		return -EINVAL;
	}

	/* Backup sector blocks to be erased */
	erasesize = ROUNDUP(nvram_space, nvram_mtd->erasesize);
	if (!(buf = kmalloc(erasesize, GFP_KERNEL))) {
		printk(KERN_WARNING "nvram_commit: out of memory\n");
		return -ENOMEM;
	}

	down(&nvram_sem);

	if ((i = erasesize - nvram_space) > 0) {
		offset = nvram_mtd->size - erasesize;
		len = 0;
		ret = nvram_mtd->_read(nvram_mtd, offset, i, &len, buf);
		if (ret || len != i) {
			printk(KERN_ERR "nvram_commit: read error ret = %d, len = %d/%d\n", ret, len, i);
			ret = -EIO;
			goto done;
		}
		header = (struct nvram_header *)(buf + i);
		magic_offset = i + ((void *)&header->magic - (void *)header);
	} else {
		offset = nvram_mtd->size - nvram_space;
		magic_offset = ((void *)&header->magic - (void *)header);
		header = (struct nvram_header *)buf;
	}
#ifdef __DAVO__
	off = offset;
#endif
	/* clear the existing magic # to mark the NVRAM as unusable
	 * we can pull MAGIC bits low without erase
	 */
	header->magic = NVRAM_CLEAR_MAGIC; /* All zeros magic */
	/* Unlock sector blocks */
	if (nvram_mtd->_unlock)
		nvram_mtd->_unlock(nvram_mtd, offset, nvram_mtd->erasesize);
	ret = nvram_mtd->_write(nvram_mtd, offset + magic_offset, sizeof(header->magic),
		&magic_len, (char *)&header->magic);
	if (ret || magic_len != sizeof(header->magic)) {
		printk(KERN_ERR "nvram_commit: clear MAGIC error\n");
		ret = -EIO;
		goto done;
	}

	header->magic = NVRAM_MAGIC;
	/* reset MAGIC before we regenerate the NVRAM,
	 * otherwise we'll have an incorrect CRC
	 */
	/* Regenerate NVRAM */
	spin_lock_irqsave(&nvram_lock, flags);
	ret = _nvram_commit(header);
	spin_unlock_irqrestore(&nvram_lock, flags);
	if (ret)
		goto done;

	/* Erase sector blocks */
	init_waitqueue_head(&wait_q);
	erase.addr = offset;
	for (erase.len = 0; offset < nvram_mtd->size - nvram_space + header->len;
	     offset += nvram_mtd->erasesize)
		erase.len += nvram_mtd->erasesize;

	erase.mtd = nvram_mtd;
	erase.callback = erase_callback;
	erase.priv = (u_long)&wait_q;
#ifdef __DAVO__
	/* force 64KB alignment with ending address */
	i = (erase.addr + erase.len) & 0xffff;
	if (i > (nvram_mtd->erasesize << 2)) {
		i = ROUNDUP((erase.addr + erase.len), 0x10000);
		if ((i + erase.addr) <= nvram_mtd->size)
			erase.len = i + erase.addr;
	}
#endif
	set_current_state(TASK_INTERRUPTIBLE);
	add_wait_queue(&wait_q, &wait);

	/* Unlock sector blocks */
	if (nvram_mtd->_unlock)
		nvram_mtd->_unlock(nvram_mtd, erase.addr, erase.len);

	if ((ret = nvram_mtd->_erase(nvram_mtd, &erase))) {
		set_current_state(TASK_RUNNING);
		remove_wait_queue(&wait_q, &wait);
		printk(KERN_ERR "nvram_commit: erase error\n");
		goto done;
	}

	/* Wait for erase to finish */
	schedule();
	remove_wait_queue(&wait_q, &wait);

	/* Write partition up to end of data area */
	header->magic = NVRAM_INVALID_MAGIC; /* All ones magic */
	offset = nvram_mtd->size - erasesize;
	i = erasesize - nvram_space + header->len;
	ret = nvram_mtd->_write(nvram_mtd, offset, i, &len, buf);
	if (ret || len != i) {
		printk(KERN_ERR "nvram_commit: write error\n");
		ret = -EIO;
		goto done;
	}

	/* Now mark the NVRAM in flash as "valid" by setting the correct
	 * MAGIC #
	 */
	header->magic = NVRAM_MAGIC;
	ret = nvram_mtd->_write(nvram_mtd, offset + magic_offset, sizeof(header->magic),
		&magic_len, (char *)&header->magic);
	if (ret || magic_len != sizeof(header->magic)) {
		printk(KERN_ERR "nvram_commit: write MAGIC error\n");
		ret = -EIO;
		goto done;
	}

	offset = nvram_mtd->size - erasesize;
#ifndef __DAVO__
	ret = nvram_mtd->_read(nvram_mtd, offset, 4, &len, buf);
#else
	ret = nvram_mtd->_read(nvram_mtd, offset, 4, &len, (u_char *)&tmp);
	nvram_backup(buf, header, off, magic_offset, erasesize);
#endif

done:
	up(&nvram_sem);
	kfree(buf);
	return ret;
}

int
nvram_getall(char *buf, int count)
{
	unsigned long flags;
	int ret;

	spin_lock_irqsave(&nvram_lock, flags);
	if (nvram_major >= 0)
		ret = _nvram_getall(buf, count);
	else
		ret = early_nvram_getall(buf, count);
	spin_unlock_irqrestore(&nvram_lock, flags);

	return ret;
}

EXPORT_SYMBOL(nvram_init);
EXPORT_SYMBOL(nvram_get);
EXPORT_SYMBOL(nvram_getall);
EXPORT_SYMBOL(nvram_set);
EXPORT_SYMBOL(nvram_unset);
EXPORT_SYMBOL(nvram_commit);

/* User mode interface below */

static ssize_t
dev_nvram_read(struct file *file, char *buf, size_t count, loff_t *ppos)
{
	char tmp[100], *name = tmp, *value;
	ssize_t ret;
	unsigned long off;

	if ((count+1) > sizeof(tmp)) {
		if (!(name = kmalloc(count+1, GFP_KERNEL)))
			return -ENOMEM;
	}

	if (copy_from_user(name, buf, count)) {
		ret = -EFAULT;
		goto done;
	}
	name[count] = '\0';

	if (*name == '\0') {
		/* Get all variables */
		ret = nvram_getall(name, count);
		if (ret == 0) {
			if (copy_to_user(buf, name, count)) {
				ret = -EFAULT;
				goto done;
			}
			ret = count;
		}
	} else {
		if (!(value = nvram_get(name))) {
			ret = 0;
			goto done;
		}

		/* Provide the offset into mmap() space */
		off = (unsigned long) value - (unsigned long) nvram_buf;

		if (copy_to_user(buf, &off, ret = sizeof(off))) {
			ret = -EFAULT;
			goto done;
		}
	}
#ifdef	_DEPRECATED
	flush_cache_all();
#endif
done:
	if (name != tmp)
		kfree(name);

	return ret;
}

static ssize_t
dev_nvram_write(struct file *file, const char *buf, size_t count, loff_t *ppos)
{
	char tmp[100], *name = tmp, *value;
	ssize_t ret;

	if (count > sizeof(tmp)) {
		if (!(name = kmalloc(count, GFP_KERNEL)))
			return -ENOMEM;
	}

	if (copy_from_user(name, buf, count)) {
		ret = -EFAULT;
		goto done;
	}
	name[ count ] = '\0';
	value = name;
	name = strsep(&value, "=");
	if (value)
		ret = nvram_set(name, value) ;
	else
		ret = nvram_unset(name) ;

	if( 0 == ret )
		ret = count;
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
	if (cmd != NVRAM_MAGIC)
		return -EINVAL;
	return nvram_commit();
}

static int
dev_nvram_mmap(struct file *file, struct vm_area_struct *vma)
{
	unsigned long offset = __pa(nvram_buf) >> PAGE_SHIFT;

	if (remap_pfn_range(vma, vma->vm_start, offset,
	                    vma->vm_end - vma->vm_start,
	                    vma->vm_page_prot))
		return -EAGAIN;

	return 0;
}

static int
dev_nvram_open(struct inode *inode, struct file * file)
{
	return 0;
}

static int
dev_nvram_release(struct inode *inode, struct file * file)
{
	return 0;
}

static struct file_operations dev_nvram_fops = {
	owner:		THIS_MODULE,
	open:		dev_nvram_open,
	release:	dev_nvram_release,
	read:		dev_nvram_read,
	write:		dev_nvram_write,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
	ioctl:		dev_nvram_ioctl,
#else
	unlocked_ioctl:	dev_nvram_ioctl,
#endif
	mmap:		dev_nvram_mmap
};

static void
dev_nvram_exit(void)
{
	int order = 0;
	struct page *page, *end;

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

	if (nvram_mtd)
		put_mtd_device(nvram_mtd);

	while ((PAGE_SIZE << order) < MAX_NVRAM_SPACE)
		order++;
	end = virt_to_page(nvram_buf + (PAGE_SIZE << order) - 1);
	for (page = virt_to_page(nvram_buf); page <= end; page++)
		ClearPageReserved(page);

	_nvram_exit();
}

static int
dev_nvram_init(void)
{
	int order = 0, ret = 0;
	struct page *page, *end;
#if defined(CONFIG_MTD) || defined(CONFIG_MTD_MODULE)
	unsigned int i;
#endif

	/* Allocate and reserve memory to mmap() */
	while ((PAGE_SIZE << order) < nvram_space)
		order++;
	end = virt_to_page(nvram_buf + (PAGE_SIZE << order) - 1);
	for (page = virt_to_page(nvram_buf); page <= end; page++) {
		SetPageReserved(page);
	}

#if defined(CONFIG_MTD) || defined(CONFIG_MTD_MODULE)
	/* Find associated MTD device */
	for (i = 0; i < MAX_MTD_DEVICES; i++) {
		nvram_mtd = get_mtd_device(NULL, i);
		if (!IS_ERR(nvram_mtd)) {
			if (!strcmp(nvram_mtd->name, "nvram") &&
			    nvram_mtd->size >= nvram_space) {
				break;
			}
			put_mtd_device(nvram_mtd);
		}
	}
	if (i >= MAX_MTD_DEVICES)
		nvram_mtd = NULL;
#endif

	/* Initialize hash table lock */
	spin_lock_init(&nvram_lock);

	/* Initialize commit semaphore */
	init_MUTEX(&nvram_sem);

	/* Register char device */
	if ((nvram_major = register_chrdev(NVRAM_MAJOR_NR, "nvram", &dev_nvram_fops)) < 0) {
		ret = nvram_major;
		goto err;
	}

	/* Initialize hash table */
	_nvram_init();

	/* Create /dev/nvram handle */
	nvram_class = class_create(THIS_MODULE, "nvram");
	if (IS_ERR(nvram_class)) {
		printk("Error creating nvram class\n");
		goto err;
	}

	/* Add the device nvram0 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
	class_device_create(nvram_class, NULL, MKDEV(nvram_major, 0), NULL, "nvram");
#else /* Linux 2.6.36 and above */
	device_create(nvram_class, NULL, MKDEV(nvram_major, 0), NULL, "nvram");
#endif	/* Linux 2.6.36 */

	return 0;

err:

	dev_nvram_exit();
	return ret;
}

/*
* This is not a module, and is not unloadable.
* Also, this module must not be initialized before
* the Flash MTD partitions have been set up, in case
* the contents are stored in Flash.
* Thus, late_initcall() macro is used to insert this
* device driver initialization later.
* An alternative solution would be to initialize
* inside the xx_open() call.
* -LR
*/
late_initcall(dev_nvram_init);

#ifdef __DAVO__
static int nvram_backup(char *buf,
			struct nvram_header *header,
			u_int32_t offset,
			u_int32_t magic_offset,
			size_t erasesize)
{
	struct mtd_info *mtd = NULL;
	int i, ret = 0;
	size_t len, magic_len;
	DECLARE_WAITQUEUE(wait, current);
	wait_queue_head_t wait_q;
	struct erase_info erase;

#ifdef CONFIG_MTD
	/* Find associated MTD device */
	for (i = 0; i < MAX_MTD_DEVICES; i++) {
		mtd = get_mtd_device(NULL, i);
		if (!IS_ERR(mtd)) {
			if (!strcmp(mtd->name, "b_nvram")
			    && mtd->size >= nvram_space)
				break;
			put_mtd_device(mtd);
		}
	}
	if (i >= MAX_MTD_DEVICES)
		mtd = NULL;
#endif
	if (mtd == NULL)
		return -1;
	/* clear the existing magic # to mark the NVRAM as unusable
	 * we can pull MAGIC bits low without erase
	 */
	header->magic = NVRAM_CLEAR_MAGIC;	/* All zeros magic */
	/* Unlock sector blocks */
	if (mtd->_unlock)
		mtd->_unlock(mtd, offset, mtd->erasesize);
	ret = mtd->_write(mtd, offset + magic_offset, sizeof(header->magic),
			  &magic_len, (char *)&header->magic);
	if (ret || magic_len != sizeof(header->magic)) {
		printk("nvram_backup: clear MAGIC error\n");
		ret = -EIO;
		goto done;
	}

	/* Erase sector blocks */
	init_waitqueue_head(&wait_q);
	erase.addr = offset;
	for (erase.len = 0; offset < mtd->size - nvram_space + header->len;
	     offset += mtd->erasesize)
	     	erase.len += mtd->erasesize;

	erase.mtd = mtd;
	erase.callback = erase_callback;
	erase.priv = (u_long)&wait_q;
#ifdef __DAVO__
	/* force 64KB alignment with ending address */
	i = (erase.addr + erase.len) & 0xffff;
	if (i > (nvram_mtd->erasesize << 2)) {
		i = ROUNDUP((erase.addr + erase.len), 0x10000);
		if ((i + erase.addr) <= nvram_mtd->size)
			erase.len = i + erase.addr;
	}
#endif
	set_current_state(TASK_INTERRUPTIBLE);
	add_wait_queue(&wait_q, &wait);
	/* Unlock sector blocks */
	if (mtd->_unlock)
		mtd->_unlock(mtd, erase.addr, erase.len);
	if ((ret = mtd->_erase(mtd, &erase))) {
		set_current_state(TASK_RUNNING);
		remove_wait_queue(&wait_q, &wait);
		printk("nvram_backup: erase error\n");
		goto done;
	}
	/* Wait for erase to finish */
	schedule();
	remove_wait_queue(&wait_q, &wait);

	/* Write partition up to end of data area */
	header->magic = NVRAM_INVALID_MAGIC;	/* All ones magic */
	offset = mtd->size - erasesize;
	i = erasesize - nvram_space + header->len;
	ret = mtd->_write(mtd, offset, i, &len, buf);
	if (ret || len != i) {
		printk("nvram_backup: write error\n");
		ret = -EIO;
		goto done;
	}
	/* Now mark the NVRAM in flash as "valid" by setting the correct
	 * MAGIC #
	 */
	header->magic = NVRAM_MAGIC2;
	ret = mtd->_write(mtd, offset + magic_offset, sizeof(header->magic),
			  &magic_len, (char *)&header->magic);
	if (ret || magic_len != sizeof(header->magic)) {
		printk("nvram_backup: write MAGIC error\n");
		ret = -EIO;
		goto done;
	}
	offset = mtd->size - erasesize;
	ret = mtd->_read(mtd, offset, 4, &len, buf);
	header->magic = NVRAM_MAGIC;
done:
	put_mtd_device(mtd);
	return ret;
}
#endif
