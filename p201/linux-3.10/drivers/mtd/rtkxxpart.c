#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/mtd/mtd.h>
#include <linux/mtd/partitions.h>

#ifdef CONFIG_BCMNVRAM
# include <bcmnvram.h>
# define BCMNVRAM_MTD_SIZE (MAX_NVRAM_SPACE << 1)
#else
# define BCMNVRAM_MTD_SIZE 0
#endif

#if defined(__DAVO__) && defined(CONFIG_JFFS2_FS)
# if (CONFIG_RTL_FLASH_SIZE > 0x1000000)
# define WDISK_SIZE 0x400000
# else
# define WDISK_SIZE 0x100000
# endif
#else
# define WDISK_SIZE 0
#endif

/* config */
#if 0
# define RTK_WAPI_SUPPORT
# define RTK_1X_SUPPORT
# define RTK_HOMEKIT_SUPPORT
# define RTK_FLATFS_SUPPORT

# define CONFIG_RTL_WAPI_SIZE			0x20000
# define CONFIG_RTL_1X_SIZE				0x20000
# define CONFIG_RTL_HOMEKIT_SIZE			0x20000
# define CONFIG_RTL_FLATFS_SIZE			0x20000
#endif

//#define MTD_PARTITION_TEST
#if defined(MTD_PARTITION_TEST)
# define MTD_PARTITION_TEST_SIZE	0x100000
#endif

#if !(defined(CONFIG_MTD_M25P80) || defined(CONFIG_RTL819X_SPI_FLASH) || defined(CONFIG_MTD_NAND))
# error "nor and nand flash not support"
#endif

/*  RTK_FLASH_SIZE  */
#if defined(CONFIG_MTD_M25P80) || defined(CONFIG_RTL819X_SPI_FLASH)
# if defined(CONFIG_RTL_TWO_SPI_FLASH_ENABLE)
#  if defined(CONFIG_MTD_CONCAT)
#   define RTK_FLASH_SIZE	(CONFIG_RTL_SPI_FLASH1_SIZE+CONFIG_RTL_SPI_FLASH2_SIZE)
#  else
#   define RTK_FLASH_SIZE	(CONFIG_RTL_SPI_FLASH1_SIZE)
#  endif
# else
#  define RTK_FLASH_SIZE	CONFIG_RTL_FLASH_SIZE
# endif
#endif
#if defined(CONFIG_MTD_NAND)
# define RTK_FLASH_SIZE	CONFIG_RTL_FLASH_SIZE
#endif

#if defined(CONFIG_RTL_FLASH_DUAL_IMAGE_ENABLE)
//#define RTK_FLASH_SIZE        CONFIG_RTL_FLASH_DUAL_IMAGE_OFFSET
#endif

#define RTK_LAST_PART_NAME	"rootfs"
#ifdef CONFIG_BCMNVRAM
# undef RTK_LAST_PART_NAME
# define RTK_LAST_PART_NAME "nvram"
#else
# if (WDISK_SIZE > 0)
#  undef RTK_LAST_PART_NAME
#  define RTK_LAST_PART_NAME "fda"
# endif
#endif

/************** MTD PARTITION *****************************/
#if defined(CONFIG_RTL_FLASH_MAPPING_ENABLE)
/**********************SPI NOR FLASH **********************/
# if defined(CONFIG_ROOTFS_JFFS2) || defined(CONFIG_ROOTFS_SQUASH)
#  if defined(CONFIG_MTD_M25P80) || defined(CONFIG_RTL819X_SPI_FLASH)
static struct mtd_partition rtl819x_parts[] = {
	{
	 name: "boot+cfg+linux",
	 size: (CONFIG_RTL_ROOT_IMAGE_OFFSET - 0),
	 offset: 0x00000000,
	 },
	{
	 name: "rootfs",
#   ifdef CONFIG_RTL_FLASH_DUAL_IMAGE_ENABLE
	 size: (CONFIG_RTL_FLASH_DUAL_IMAGE_OFFSET - CONFIG_RTL_ROOT_IMAGE_OFFSET),
#   else
	 size: (RTK_FLASH_SIZE - CONFIG_RTL_ROOT_IMAGE_OFFSET - WDISK_SIZE - BCMNVRAM_MTD_SIZE),
#   endif
	 offset: CONFIG_RTL_ROOT_IMAGE_OFFSET,
	 }
#   ifdef __DAVO__
#    if (WDISK_SIZE > 0)
	, {
	 name: "fda",
	 size: WDISK_SIZE,
	 offset: (CONFIG_RTL_FLASH_SIZE - (MAX_NVRAM_SPACE << 1) - WDISK_SIZE),
	 }
#    endif
#    ifdef CONFIG_BCMNVRAM
	, {
	 name: "b_nvram",
	 size: MAX_NVRAM_SPACE,
	 offset: (CONFIG_RTL_FLASH_SIZE - (MAX_NVRAM_SPACE << 1)),
	 }

	, {
	 name: "nvram",
	 size: MAX_NVRAM_SPACE,
	 offset: (CONFIG_RTL_FLASH_SIZE - MAX_NVRAM_SPACE),
	 }
#    endif			/* CONFIG_BCMNVRAM */
#   else			/* __DAVO__ */
#    if defined(CONFIG_BT_REPEATER_CONFIG)
#     if CONFIG_RTL_BT_PARTITION_SIZE	!= 0x0
	,
	{
	 name: "bluetooth",
	 size: (CONFIG_RTL_BT_PARTITION_SIZE),
	 offset: RTK_FLASH_SIZE,
	 }
#     endif
#    endif
#    if CONFIG_RTL_WAPI_PARTITION_SIZE != 0x0
	,
	{
	 name: "wapi",
	 size: (CONFIG_RTL_WAPI_PARTITION_SIZE),
	 offset: RTK_FLASH_SIZE,
	 }
#    endif
#    if CONFIG_RTL_1X_PARTITION_SIZE != 0x0
	,
	{
	 name: "1x",
	 size: (CONFIG_RTL_1X_PARTITION_SIZE),
	 offset: RTK_FLASH_SIZE,
	 }
#    endif
#    if CONFIG_RTL_HOMEKIT_PARTITION_SIZE != 0x0
	,
	{
	 name: "homekit",
	 size: (CONFIG_RTL_HOMEKIT_PARTITION_SIZE),
	 offset: RTK_FLASH_SIZE,
	 }
#    endif
#    if CONFIG_RTL_CWMP_TRANSFER_PARTITION_SIZE != 0x0
	,
	{
	 name: "cwmp transfer",
	 size: (CONFIG_RTL_CWMP_TRANSFER_PARTITION_SIZE),
	 offset: RTK_FLASH_SIZE,
	 }
#    endif
#    if CONFIG_RTL_CWMP_NOTIFICATION_PARTITION_SIZE != 0x0
	,
	{
	 name: "cwmp notification",
	 size: (CONFIG_RTL_CWMP_NOTIFICATION_PARTITION_SIZE),
	 offset: RTK_FLASH_SIZE,
	 }
#    endif
#    if CONFIG_RTL_CWMP_CACERT_PARTITION_SIZE != 0x0
	,
	{
	 name: "cwmp cacert",
	 size: (CONFIG_RTL_CWMP_CACERT_PARTITION_SIZE),
	 offset: RTK_FLASH_SIZE,
	 }
#    endif
#    if CONFIG_RTL_JFFS2_FILE_PARTITION_SIZE != 0x0
	,
	{
	 name: "jffs2 file",
	 size: (CONFIG_RTL_JFFS2_FILE_PARTITION_SIZE),
	 offset: RTK_FLASH_SIZE,
	 }
#    endif
#    if 0			//defined(MTD_PARTITION_TEST)
	,
	{
	 name: "mtd_test",
	 size: (MTD_PARTITION_TEST_SIZE),
	 offset: RTK_FLASH_SIZE,
	 }

#    endif
	// dual image support
#    if defined(CONFIG_RTL_FLASH_DUAL_IMAGE_ENABLE)
	,
	{
	 name: "boot+cfg+linux2",
	 size: (CONFIG_RTL_ROOT_IMAGE_OFFSET - 0),
	 offset: 0x00000000 + CONFIG_RTL_FLASH_DUAL_IMAGE_OFFSET,
	 }
	,
	{
	 name: "rootfs2",
	 size: (RTK_FLASH_SIZE - CONFIG_RTL_FLASH_DUAL_IMAGE_OFFSET - CONFIG_RTL_ROOT_IMAGE_OFFSET),
	 offset: CONFIG_RTL_ROOT_IMAGE_OFFSET + CONFIG_RTL_FLASH_DUAL_IMAGE_OFFSET,
	 }
#     if CONFIG_RTL_WAPI_PARTITION_SIZE != 0x0
	,
	{
	 name: "wapi2",
	 size: (CONFIG_RTL_WAPI_PARTITION_SIZE),
	 offset: RTK_FLASH_SIZE,
	 }
#     endif
#     if CONFIG_RTL_1X_PARTITION_SIZE != 0x0
	,
	{
	 name: "1x2",
	 size: (CONFIG_RTL_1X_PARTITION_SIZE),
	 offset: RTK_FLASH_SIZE,
	 }
#     endif
#     if CONFIG_RTL_HOMEKIT_PARTITION_SIZE != 0x0
	,
	{
	 name: "homekit2",
	 size: (CONFIG_RTL_HOMEKIT_PARTITION_SIZE),
	 offset: RTK_FLASH_SIZE,
	 }
#     endif
#     if CONFIG_RTL_CWMP_TRANSFER_PARTITION_SIZE != 0x0
	,
	{
	 name: "cwmp transfer2",
	 size: (CONFIG_RTL_CWMP_TRANSFER_PARTITION_SIZE),
	 offset: RTK_FLASH_SIZE,
	 }
#     endif
#     if CONFIG_RTL_CWMP_NOTIFICATION_PARTITION_SIZE != 0x0
	,
	{
	 name: "cwmp notification2",
	 size: (CONFIG_RTL_CWMP_NOTIFICATION_PARTITION_SIZE),
	 offset: RTK_FLASH_SIZE,
	 }
#     endif
#     if CONFIG_RTL_CWMP_CACERT_PARTITION_SIZE != 0x0
	,
	{
	 name: "cwmp cacert2",
	 size: (CONFIG_RTL_CWMP_CACERT_PARTITION_SIZE),
	 offset: RTK_FLASH_SIZE,
	 }
#     endif
#     if CONFIG_RTL_JFFS2_FILE_PARTITION_SIZE != 0x0
	,
	{
	 name: "jffs2 file2",
	 size: (CONFIG_RTL_JFFS2_FILE_PARTITION_SIZE),
	 offset: RTK_FLASH_SIZE,
	 }
#     endif
#    endif
#   endif			/* !__DAVO__ */
};
#  endif
/*********************************************************/
/******************* NAND FLASH ***************************/
#  if !defined(CONFIG_RTK_NAND_FLASH_STORAGE)
#   if defined(CONFIG_MTD_NAND)
static struct mtd_partition rtl819x_parts[] = {
	{
	 name: "boot",
	 size: 0x500000,
	 offset: 0x00000000,
	 },
	{
	 name: "setting",
	 size: 0x300000,
	 offset: 0x500000,
	 },
	{
	 name: "linux",
	 size: (CONFIG_RTL_ROOT_IMAGE_OFFSET - 0x800000),
	 offset: 0x800000,
	 },
	{
	 name: "rootfs",
#    ifdef CONFIG_RTL_FLASH_DUAL_IMAGE_ENABLE
	 size: (CONFIG_RTL_FLASH_DUAL_IMAGE_OFFSET - CONFIG_RTL_ROOT_IMAGE_OFFSET),
#    else
	 size: (RTK_FLASH_SIZE - CONFIG_RTL_ROOT_IMAGE_OFFSET),
#    endif
	 offset: CONFIG_RTL_ROOT_IMAGE_OFFSET,
	 }
#    if defined(CONFIG_RTL_FLASH_DUAL_IMAGE_ENABLE)
	,
	{
	 name: "boot2",
	 size: 0x500000,
	 offset: 0x00000000 + CONFIG_RTL_FLASH_DUAL_IMAGE_OFFSET,
	 }
	,
	{
	 name: "setting2",
	 size: 0x300000,
	 offset: 0x500000 + CONFIG_RTL_FLASH_DUAL_IMAGE_OFFSET,
	 },
	{
	 name: "linux2",
	 size: (CONFIG_RTL_ROOT_IMAGE_OFFSET - 0x800000),
	 offset: 0x800000 + CONFIG_RTL_FLASH_DUAL_IMAGE_OFFSET,
	 },
	{
	 name: "rootfs2",
	 size: (RTK_FLASH_SIZE - CONFIG_RTL_FLASH_DUAL_IMAGE_OFFSET - CONFIG_RTL_ROOT_IMAGE_OFFSET),
	 offset: CONFIG_RTL_ROOT_IMAGE_OFFSET + CONFIG_RTL_FLASH_DUAL_IMAGE_OFFSET,
	 }
#    endif
};
#   endif
#  endif
	/***************RAMFS as rootfs *****************/
# elif defined(CONFIG_ROOTFS_RAMFS)
#  if defined(CONFIG_MTD_M25P80) || defined(CONFIG_RTL819X_SPI_FLASH)
static struct mtd_partition rtl819x_parts[] = {
	{
	 name: "boot+cfg+linux+rootfs",
	 size: (RTK_FLASH_SIZE - 0),
	 offset: 0x00000000,
	 },
};
#  endif

#  if defined(CONFIG_MTD_NAND)
static struct mtd_partition rtl819x_parts[] = {
	{
	 name: "boot",
	 size: 0x500000,
	 offset: 0x00000000,
	 },
	{
	 name: "setting",
	 size: 0x300000,
	 offset: 0x500000,
	 }
};
#  endif
# endif
/*********************************************************/
#else
	/*****************not support CONFIG_RTL_FLASH_MAPPING_ENABLE ***************/
static struct mtd_partition rtl819x_parts[] = {
	{
	 name: "boot+cfg+linux",
	 size: 0x00130000,
	 offset: 0x00000000,
	 },
	{
	 name: "rootfs",
	 size: 0x002D0000,
	 offset: 0x00130000,
	 }
}
#endif

#ifdef CONFIG_RTL_TWO_SPI_FLASH_ENABLE
# ifndef CONFIG_MTD_CONCAT
static struct mtd_partition rtl819x_parts2[] = {
	{
	 name: "data",
	 size: CONFIG_RTL_SPI_FLASH2_SIZE,
	 offset: 0x00000000,
	 }
};
# endif
#endif

/*********************************************************/
static int rtkxxpart_check_parttion_erasesize_aligned(struct mtd_info *master)
{
	int i = 0;
	uint64_t offset = 0, size = 0;
	/* check if mtd partition offset && size erasesize aligned */
	for (i = 0; i < ARRAY_SIZE(rtl819x_parts); i++) {
		offset = rtl819x_parts[i].offset;
		size = rtl819x_parts[i].size;
		//printk("%s offset=0x%llx size=0x%llx erasesize=0x%x\n",
		//      rtl819x_parts[i].name,rtl819x_parts[i].offset,
		//              rtl819x_parts[i].size,master->erasesize);
		if (do_div(offset, master->erasesize) != 0 ||
		    do_div(size, master->erasesize) != 0) {
			printk("%s offset=0x%llx size=0x%llx erasesize=0x%x!!!! not aligned!!!\n",
			       rtl819x_parts[i].name, rtl819x_parts[i].offset,
			       rtl819x_parts[i].size, master->erasesize);
			return -1;
		}
	}

	return 0;
}

static int rtkxxpart_detect_flash_map(struct mtd_info *master)
{
	int i;
	unsigned int size = 0;
	int dualpartition = 0;
#if defined(CONFIG_RTL_FLASH_DUAL_IMAGE_ENABLE)
	unsigned char lastpartion2[16];
#endif
#if defined(CONFIG_ROOTFS_RAMFS)
	return rtkxxpart_check_parttion_erasesize_aligned(master);
#endif

#if defined(CONFIG_RTL_FLASH_DUAL_IMAGE_ENABLE)
	strcpy(lastpartion2, RTK_LAST_PART_NAME);
	strcat(lastpartion2, "2");
#endif

#ifdef CONFIG_RTL_FLASH_DUAL_IMAGE_ENABLE
	for (i = 0; i < ARRAY_SIZE(rtl819x_parts); i++) {
# if defined(CONFIG_MTD_M25P80) || defined(CONFIG_RTL819X_SPI_FLASH)
		if (!strcmp(rtl819x_parts[i].name, "boot+cfg+linux2"))
# elif defined(CONFIG_MTD_NAND)
		if (!strcmp(rtl819x_parts[i].name, "boot2"))
# endif
			dualpartition = i;
	}
#else
	dualpartition = ARRAY_SIZE(rtl819x_parts);
#endif

	for (i = dualpartition - 1; i >= 0; i--) {
		if (strcmp(rtl819x_parts[i].name, RTK_LAST_PART_NAME)) {
			size += rtl819x_parts[i].size;
#ifdef CONFIG_RTL_FLASH_DUAL_IMAGE_ENABLE
			rtl819x_parts[i].offset = CONFIG_RTL_FLASH_DUAL_IMAGE_OFFSET - size;
#else
			rtl819x_parts[i].offset = RTK_FLASH_SIZE - size;
#endif
		} else {
			if (rtl819x_parts[i].size < size) {
				printk("donnot have space for rootfs partition\n");
				return -1;
			}
			rtl819x_parts[i].size = rtl819x_parts[i].size - size;
			break;
		}
	}

#ifdef CONFIG_RTL_FLASH_DUAL_IMAGE_ENABLE
	size = 0;
	for (i = ARRAY_SIZE(rtl819x_parts) - 1; i >= dualpartition; i--) {
		if (strcmp(rtl819x_parts[i].name, lastpartion2)) {
			size += rtl819x_parts[i].size;
			rtl819x_parts[i].offset = RTK_FLASH_SIZE - size;
		} else {
			if (rtl819x_parts[i].size < size) {
				printk("donnot have space for rootfs2 partition\n");
				return -1;
			}
			rtl819x_parts[i].size = rtl819x_parts[i].size - size;
			break;
		}
	}
#endif

	if (rtkxxpart_check_parttion_erasesize_aligned(master) != 0)
		return -1;

#ifdef CONFIG_MTD_NAND
	/* check if nand reserve %10 space for skip/remap bbt */
	int rtkn_check_nand_partition(struct mtd_partition *parts, int partnum);
	if (rtkn_check_nand_partition(rtl819x_parts, ARRAY_SIZE(rtl819x_parts)) < 0) {
		return -1;
	}
#endif

	return 0;
}

#ifdef __DAVO__
static void mtd_part_stop_gap(struct mtd_partition *part, int i, size_t size)
{
	if (i > 0)
		part[-1].size = part->offset - part[-1].offset;
	if ((i + 1) < size)
		part->size = part[1].offset - part->offset;
}

/* be contiguous with the front and rear partitions as possible as */
static int mtd_part_resize(const char *name, uint64_t new_size)
{
	uint64_t tmp;
	int64_t diff;
	int i;

	for (i = 0; i < ARRAY_SIZE(rtl819x_parts); i++) {
		struct mtd_partition *part = &rtl819x_parts[i];
		if (!strcmp(part->name, name)) {
			/* fill up gap if any */
			mtd_part_stop_gap(part, i, ARRAY_SIZE(rtl819x_parts));
			diff = new_size - part->size;
			if (diff < 0) {
				if (i > 0) {
					part[-1].size += (0LL - diff);
					part->offset += (0LL - diff);
				} else if ((i + 1) < ARRAY_SIZE(rtl819x_parts)) {
					tmp = part[1].offset;
					part[1].offset = new_size;
					part[1].size += (tmp - part[1].offset);
				}
				part->size = new_size;
			} else if (diff > 0) {
				/* greedy extenstion */
				if (i > 0 && part[-1].size > diff) {
					part[-1].size -= diff;
					part->offset -= diff;
					part->size = new_size;
				} else if ((i + 1) < ARRAY_SIZE(rtl819x_parts)) {
					tmp = part[1].offset - part->offset;
					if (tmp >= new_size)
						part->size = new_size;
					else if ((tmp + part[1].size) > new_size) {
						part->size = new_size;
						tmp = part[1].offset;
						part[1].offset = part->offset + part->size;
						part[1].size -= (part[1].offset - tmp);
					}
				}
			}
			return (part->size == new_size) ? 0 : -1;
		}
	}
	return -1;
}
#endif

#ifdef CONFIG_BCMNVRAM
static void concat_mtdpart(struct mtd_partition *mtd, int mtdsiz, uint64_t fs)
{
	int i;

	for (i = 0; i < mtdsiz; i++) {
		if (strstr(mtd[i].name, "root")) {
			mtd[i].offset = (fs) ? fs : CONFIG_RTL_ROOT_IMAGE_OFFSET;
			if ((i + 1) < mtdsiz)
				mtd[i].size = mtd[i + 1].offset - mtd[i].offset;
			else
				mtd[i].size = CONFIG_RTL_ROOT_IMAGE_OFFSET - mtd[i].offset;
			if ((i - 1) > -1)
				mtd[i - 1].size = mtd[i].offset - mtd[i - 1].offset;
			break;
		}
	}
}

static u8 hndcrc8(u8 *pdata, long len, u8 crc)
{
	int i;

	while (len > 0) {
		crc = crc ^ *pdata++;
		for (i = 0; i < 8; i++) {
			if ((crc & 1)) {
				crc >>= 1;
				crc ^= 0xab;
			} else
				crc >>= 1;
		}
		len--;
	}
	return crc;
}

static u8 nvram_calc_crc(struct nvram_header *nvh)
{
	struct nvram_header tmp;
	u8 crc;

	/* Little-endian CRC8 over the last 11 bytes of the header */
	tmp.crc_ver_init = htonl((nvh->crc_ver_init & NVRAM_CRC_VER_MASK));
	tmp.kern_start = htonl(nvh->kern_start);
	tmp.rootfs_start = htonl(nvh->rootfs_start);

	crc = hndcrc8((u8 *)&tmp + NVRAM_CRC_START_POSITION,
		      sizeof(struct nvram_header) - NVRAM_CRC_START_POSITION,
		      CRC8_INIT_VALUE);
	/* Continue CRC8 over data bytes */
	return hndcrc8((u8 *)&nvh[1], nvh->len - sizeof(struct nvram_header), crc);
}

static int parse_bootline(struct mtd_info *master, u32 *fs)
{
	struct nvram_header *h;
	size_t len;
	u32 off, lim;
	int rc = -1;

	lim = 0x00200000;		/* Minimum flash size - 2MB */
	off = master->size;
	for (h = (struct nvram_header *)kmalloc(MAX_NVRAM_SPACE, GFP_KERNEL);
	     h && (off >= lim); off >>= 1) {
		master->_read(master, off - MAX_NVRAM_SPACE, sizeof(*h), &len, (u_char *)h);
		if (h->magic != NVRAM_MAGIC)
			continue;
		if (h->len > MAX_NVRAM_SPACE)
			continue;
		master->_read(master, off - MAX_NVRAM_SPACE + sizeof(*h),
			MAX_NVRAM_SPACE - sizeof(*h), &len, (u_char *)&h[1]);
		if (nvram_calc_crc(h) == (u8)h->crc_ver_init) {
			if (h->kern_start &&
			    (h->kern_start < h->rootfs_start) &&
			    (h->rootfs_start < master->size)) {
				*fs = h->rootfs_start;
				rc = 0;
			}
			break;
		}
	}
	kfree(h);
	return rc;
}
#endif /* CONFIG_BCMNVRAM */

/* may not need rtl819x_parts */
static int rtkxxpart_parse(struct mtd_info *master,
			   struct mtd_partition **pparts,
			   struct mtd_part_parser_data *data)
{
	int nrparts = 0;
	struct mtd_partition *parts = NULL;
#ifdef __DAVO__
	int i;
#endif
	/* for rtkxxpart, if enabled CONFIG_RTL_TWO_SPI_FLASH_ENABLE but not enabled CONFIG_MTD_CONCAT, origin defined the mtddevicenum */
	if (data == NULL || data->origin == 0) {
		nrparts = sizeof(rtl819x_parts) / sizeof(struct mtd_partition);
	}
#if defined(CONFIG_RTL_TWO_SPI_FLASH_ENABLE)  && !defined(CONFIG_MTD_CONCAT)
	else {
		nrparts = sizeof(rtl819x_parts2) / sizeof(struct mtd_partition);
	}
#endif
#ifdef __DAVO__
	if (master->size != RTK_FLASH_SIZE) {
		for (i = ARRAY_SIZE(rtl819x_parts) - 1; i >= 0; i--) {
			if (!strncmp(rtl819x_parts[i].name, "fda", sizeof("fda") - 1) ||
			strstr(rtl819x_parts[i].name, "nvram"))
				rtl819x_parts[i].offset =
					(int64_t)rtl819x_parts[i].offset + (int64_t)(master->size - RTK_FLASH_SIZE);
		}
		mtd_part_resize("fda", (master->size > 0x1000000) ? 0x400000 : 0x100000);
	}
#endif
#ifdef CONFIG_BCMNVRAM
	do {
		u32 fs_offset = 0;
		if (!parse_bootline(master, &fs_offset))
			concat_mtdpart(rtl819x_parts, ARRAY_SIZE(rtl819x_parts), fs_offset);
	} while (0);
#endif
	parts = kzalloc(sizeof(*parts) * nrparts + 10 * nrparts, GFP_KERNEL);
	if (!parts) {
		return -ENOMEM;
	}

	if (rtkxxpart_detect_flash_map(master) < 0) {
		printk("dynamic alloc partition fail\n");
		master->size = 0;
		/* COVERITY: RESOURCE_LEAK */
		if (parts)
			kfree(parts);
		return -1;
	}

	if (data == NULL || data->origin == 0) {
		memcpy(parts, rtl819x_parts, sizeof(rtl819x_parts));
	}
#if defined(CONFIG_RTL_TWO_SPI_FLASH_ENABLE) && !defined(CONFIG_MTD_CONCAT)
	else
		memcpy(parts, rtl819x_parts2, sizeof(rtl819x_parts2));
#endif
	*pparts = parts;

	return nrparts;
};

static struct mtd_part_parser rtkxxpart_mtd_parser = {
	.owner = THIS_MODULE,
	.parse_fn = rtkxxpart_parse,
	.name = "rtkxxpart",
};

static int __init rtkxxpart_init(void)
{
	return register_mtd_parser(&rtkxxpart_mtd_parser);
}

static void __exit rtkxxpart_exit(void)
{
	deregister_mtd_parser(&rtkxxpart_mtd_parser);
}

module_init(rtkxxpart_init);
module_exit(rtkxxpart_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("MTD partitioning for realtek flash memories");
