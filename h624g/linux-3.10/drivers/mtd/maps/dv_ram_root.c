#if DAVO_ROOTFS_RAM

#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <asm/io.h>
#include <linux/mtd/mtd.h>
#include <linux/mtd/map.h>
#include <linux/root_dev.h>
#include <linux/mtd/partitions.h>
#include <linux/kconfig.h>
#include <linux/delay.h>

#include "../mtdcore.h"

#ifdef CONFIG_MTD_CONCAT
#include <linux/mtd/concat.h>
#endif
#ifdef CONFIG_BCMNVRAM
#include <bcmnvram.h>
#endif

#include "squashfs_fs.h"

static struct map_info rr_map;
static struct mtd_info *rr_mtd;

#define FL_ADDR(x) (0xbd000000 + (x))

static inline uint64_t SWAP_ENDIAN(uint64_t x)
{
	x = (x & 0x00000000FFFFFFFFULL) << 32 | (x & 0xFFFFFFFF00000000ULL) >> 32;
	x = (x & 0x0000FFFF0000FFFFULL) << 16 | (x & 0xFFFF0000FFFF0000ULL) >> 16;
	x = (x & 0x00FF00FF00FF00FFULL) << 8  | (x & 0xFF00FF00FF00FF00ULL) >> 8;
	return x;
}


static int find_squashfs_len(uint32 fs_offset, int *sz)
{
	struct squashfs_super_block hdr;
	int sz_real;

	memcpy(&hdr, (void *)FL_ADDR(fs_offset), sizeof(hdr));
	if (memcmp(&hdr, "hsqs", 4)!=0) {
		printk("%s():%d sqsh not found\n", __FUNCTION__, __LINE__);
		return -1;
	}

	sz_real = (int)SWAP_ENDIAN(hdr.bytes_used)+sizeof(struct squashfs_super_block);
	*sz = (sz_real + PAGE_SIZE-1) & (~(PAGE_SIZE-1));
	printk("squashfs rootfs bytes %d(orig %d,%d)\n", *sz, sz_real, sz_real-sizeof(struct squashfs_super_block));
	return 0;
}

int make_ram_root_fs(struct map_info *f_map, uint32 fs_offset) 
{
	int sz;
	unsigned long *p;

	if (find_squashfs_len(fs_offset, &sz)<0) {
		printk("ram root failed %d\n", __LINE__);
		return -2;
	}

	p = (void *)__get_free_pages(GFP_ATOMIC, get_order(sz));
	if (!p) {
		printk("__get_free_pages %d(%d) failed\n", sz, get_order(sz));
		printk("ram root failed %d\n", __LINE__);
		return -3;
	} else {
		printk("rootfs additional memory allocation %d(2^%d) success\n", sz, get_order(sz));
	}
	memcpy(p, (void *)FL_ADDR(fs_offset), sz);

	rr_map.name = "ram_root";
	rr_map.bankwidth = 4;
	rr_map.phys = virt_to_phys(p);
	rr_map.size = sz;
	rr_map.virt = p;

	simple_map_init(&rr_map);

	rr_mtd = do_map_probe("map_ram", &rr_map);

	if (rr_mtd) {
		rr_mtd->owner = THIS_MODULE;
		add_mtd_device(rr_mtd);
		ROOT_DEV = MKDEV(MTD_BLOCK_MAJOR, rr_mtd->index);
		return 0;
	} else {
		free_pages((unsigned long)p, get_order(sz));
		printk("ram root failed %d\n", __LINE__);
		return -1;
	}
}

#endif
