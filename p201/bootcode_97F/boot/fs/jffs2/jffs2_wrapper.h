#ifndef __JFFS2_WRAPPER_H__
#define __JFFS2_WRAPPER_H__

#include <linux/types.h>
#include <asm/string.h>
#include <jffs2/load_kernel.h>

#ifdef CONFIG_CMD_FLASH
#define SPI_NOR_START_ADDR	0xb0000000
#endif


typedef unsigned char   uchar;
typedef unsigned char	Bytef;
typedef unsigned int   	uInt;

#define le32_to_cpu(x) ((unsigned int)(x))
#define cpu_to_le32(x) ((unsigned int)(x))

#define WATCHDOG_RESET()
#define __BYTE_ORDER  		__LITTLE_ENDIAN

#define simple_strtoul		strtoul
#define printf(fmt,args...)	prom_printf(fmt ,##args)
#define puts(fmt,args...)	prom_printf(fmt ,##args)

void * memcpy(void * dest,const void *src,size_t count);
int rtk_mtdparts_init(struct part_info* part);
uint32_t __div64_32(uint64_t *n, uint32_t base);


#define min_t(type, x, y) ({			\
	type __min1 = (x);			\
	type __min2 = (y);			\
	__min1 < __min2 ? __min1: __min2; })


/* div */
# define do_div(n,base) ({				\
	uint32_t __base = (base);			\
	uint32_t __rem;					\
	(void)(((typeof((n)) *)0) == ((uint64_t *)0));	\
	if (((n) >> 32) == 0) {			\
		__rem = (uint32_t)(n) % __base;		\
		(n) = (uint32_t)(n) / __base;		\
	} else						\
		__rem = __div64_32(&(n), __base);	\
	__rem;						\
 })

/* Wrapper for do_div(). Doesn't modify dividend and returns
 * the result, not reminder.
 */
static inline uint64_t lldiv(uint64_t dividend, uint32_t divisor)
{
	uint64_t __res = dividend;
	do_div(__res, divisor);
	return(__res);
}

#endif
