/**
 *  SPI Flash common control code.
 *  (C) 2006 Atmark Techno, Inc.
 */

#include <linux/init.h>
#include <linux/kernel.h>
//#include <linux/config.h>
#include <linux/module.h>
#include <linux/types.h>

#include <linux/mtd/mtd.h>
#include <linux/mtd/map.h>
#include <linux/mtd/gen_probe.h>

#include "spi_flash.h"

//#define MTD_SPI_DEBUG

#if defined(MTD_SPI_DEBUG)
# define KDEBUG(args...) printk(args)
#else
# define KDEBUG(args...) do {} while (0)
#endif

#ifdef CONFIG_RTL_8198C
# define LX_CONTROL		0xb8000014
# define SYS_MSRR		0xb8001038
# define REG32(reg)		(*(volatile unsigned int *)(reg))

# if 1
#  define LOCK_LX0_BUS() \
do { \
	REG32(LX_CONTROL) |= (1 << 2); /* request locking Lx0 bus */ \
	while ((REG32(LX_CONTROL) & (1 << 12)) == 0) ; /* wait for Lx0 bus lock okay */ \
	while ((REG32(SYS_MSRR) & (1 << 30)) == 0) ; /* wait for No on going DRAM command */ \
} while(0)

#  define RELEASE_LX0_BUS() \
do { \
	REG32(LX_CONTROL) &= ~(1 << 2); /* release Lx0 bus */ \
} while(0)
# endif

# if 0
#  define LOCK_LX0_BUS() \
do { \
	REG32(LX_CONTROL) |= ( 3<< 2);				/* request locking Lx0 bus */ \
	while ((REG32(LX_CONTROL) & (3 << 12)) != (3 << 12)) ;	/* wait for Lx0 bus lock okay */ \
	while ((REG32(SYS_MSRR) & (1 << 30)) == 0) ;		/* wait for No on going DRAM command */ \
} while(0)

#  define RELEASE_LX0_BUS() \
do { \
	REG32(LX_CONTROL) &= ~(3<<2); /* release Lx0 bus */ \
} while(0)

//#else
//#define LOCK_LX0_BUS()
//#define RELEASE_LX0_BUS()
# endif
#endif

#ifdef RTK_FLASH_SPIN_LOCK
static DEFINE_SPINLOCK(spi_slock);
#endif

#if DAVO_WDT_SPI_3B4B_PATCH
extern void dv_spi_EN4B(void);
extern void dv_spi_EX4B(void);
unsigned long dv_cnt_en4b;

static void should_en4b(struct spi_chip_info *ci, u32 addr, int len, u32 halfsz)
{
# if DAVO_4B_ONLY_SUPPORT
	if (ci->spi_4b_only)	/* 735F */
		dv_spi_EN4B();
	else
# endif
	{
		if ((addr + len) < halfsz)
			return;
		dv_spi_EN4B();
		dv_cnt_en4b++;
	}
}

static void should_ex4b(struct spi_chip_info *ci)
{
# if DAVO_4B_ONLY_SUPPORT
	if (!ci->spi_4b_only)
# endif
		dv_spi_EX4B();
}
#else
#define should_en4b(c, a, l, h)	do {} while (0)
#define should_ex4b(c)	do {} while (0)
#endif

static void __mtd_spi_lock(struct spi_chip_info *chip)
{
#ifdef RTK_FLASH_MUTEX
	mutex_lock(&chip->lock);
#endif
#ifdef RTK_FLASH_SPIN_LOCK
	spin_lock(&spi_slock);
#endif
#ifdef CONFIG_RTL_8198C
	LOCK_LX0_BUS();
#endif
}

static void __mtd_spi_unlock(struct spi_chip_info *chip)
{
#ifdef CONFIG_RTL_8198C
	RELEASE_LX0_BUS();
#endif
#ifdef RTK_FLASH_SPIN_LOCK
	spin_unlock(&spi_slock);
#endif
#ifdef RTK_FLASH_MUTEX
	mutex_unlock(&chip->lock);
#endif
}

#define	ROUNDUP(x, y)		(((x) + ((y) - 1)) & ~((y) - 1))

int mtd_spi_erase(struct mtd_info *mtd, struct erase_info *instr)
{
	struct map_info *map = mtd->priv;
	struct spi_chip_info *chip_info = (struct spi_chip_info *)map->fldrv_priv;
	unsigned long adr, len;
	int ret = 0;

	if (!chip_info->erase)
		return -EOPNOTSUPP;
#if 0	// skip 1st block erase
	if (instr->addr < (mtd->erasesize)) {
		instr->state = MTD_ERASE_DONE;
		return 0;
	}
#endif
	if (instr->addr & (mtd->erasesize - 1))
		return -EINVAL;

	if ((instr->len + instr->addr) > mtd->size)
		return -EINVAL;

	adr = instr->addr;
	len = instr->len;

	KDEBUG("mtd_spi_erase():: adr: 0x%08lx, len: 0x%08lx\n", adr, len);

	len = ROUNDUP(len, mtd->erasesize);

	__mtd_spi_lock(chip_info);
	should_en4b(chip_info, adr, len, mtd->size / 2);

	while (len) {
#ifdef __DAVO__
		if (chip_info->berase && !(adr & (0x10000 - 1)) && (len >= 0x10000)) {
			if (!chip_info->berase(adr, chip_info->chip_select)) {
				adr += 0x10000;
				len -= 0x10000;
				continue;
			}
		} else
#endif
		ret = chip_info->erase(adr, chip_info->chip_select);
		if (ret)
			break;
		adr += mtd->erasesize;
		len -= mtd->erasesize;
	}

	should_ex4b(chip_info);
	__mtd_spi_unlock(chip_info);

	instr->state = (!ret) ? MTD_ERASE_DONE : MTD_ERASE_FAILED;
	if (instr->callback)
		instr->callback(instr);

	return (ret) ? ((ret > 0) ? (0 - ret) : ret) : 0;
}

int mtd_spi_read(struct mtd_info *mtd, loff_t from, size_t len, size_t *retlen, u_char *buf)
{
	struct map_info *map = mtd->priv;
	struct spi_chip_info *chip_info = (struct spi_chip_info *)map->fldrv_priv;
	int ret;

	if (!chip_info->read)
		return -EOPNOTSUPP;

	KDEBUG("mtd_spi_read():: adr: 0x%08x, len: %08x, cs=%d\n", (u32) from, len, chip_info->chip_select);

	__mtd_spi_lock(chip_info);
	should_en4b(chip_info, from, len, mtd->size / 2);

	ret = chip_info->read(from, (u32)buf, len, chip_info->chip_select);
	/* do_spi_read always returns 0 */
	if (!ret && retlen)
		*retlen = len;

	should_ex4b(chip_info);
	__mtd_spi_unlock(chip_info);

	return (ret) ? ((ret > 0) ? (0 - ret) : ret) : 0;
}

int mtd_spi_write(struct mtd_info *mtd, loff_t to, size_t len, size_t * retlen, const u_char * buf)
{
	struct map_info *map = mtd->priv;
	struct spi_chip_info *chip_info = (struct spi_chip_info *)map->fldrv_priv;
	int ret;

	if (!chip_info->write)
		return -EOPNOTSUPP;

	KDEBUG(" mtd_spi_write():: adr: 0x%08x, len: 0x%08x, cs=%d\n", (u32) to, len, chip_info->chip_select);

	__mtd_spi_lock(chip_info);
	should_en4b(chip_info, to, len, mtd->size / 2);

	ret = chip_info->write((u32)buf, to, len, chip_info->chip_select);
	/* do_spi_write always returns 0 */
	if (!ret && retlen)
		*retlen = len;

	should_ex4b(chip_info);
	__mtd_spi_unlock(chip_info);

	return (ret) ? ((ret > 0) ? (0 - ret) : ret) : 0;
}

void mtd_spi_sync(struct mtd_info *mtd)
{
	/* Operation not supported on transport endpoint */
}

int mtd_spi_suspend(struct mtd_info *mtd)
{
	/* Operation not supported on transport endpoint */
	return -EOPNOTSUPP;
}

void mtd_spi_resume(struct mtd_info *mtd)
{
	/* Operation not supported on transport endpoint */
}

EXPORT_SYMBOL(mtd_spi_erase);
EXPORT_SYMBOL(mtd_spi_read);
EXPORT_SYMBOL(mtd_spi_write);
EXPORT_SYMBOL(mtd_spi_sync);
EXPORT_SYMBOL(mtd_spi_suspend);
EXPORT_SYMBOL(mtd_spi_resume);
