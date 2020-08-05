#ifndef __DVFLAG_H
#define __DVFLAG_H

typedef enum {
	DVFLGIO_SETMASK_INDEX,
	DVFLGIO_GETMASK_INDEX,
	DVFLGIO_MAX_INDEX
} DVFLGIOCTL_INDEX;

/* Defines. */
#define DVFLGDRV_MAJOR         209     /* arbitrary unused value */

#define DVFLGIO_SETMASK \
	_IOWR(DVFLGDRV_MAJOR, DVFLGIO_SETMASK_INDEX, int)

#define DVFLGIO_GETMASK \
	_IOWR(DVFLGDRV_MAJOR, DVFLGIO_GETMASK_INDEX, int)

#define DF_WANLINK      (1 << 0)
#define DF_LANLINK1     (1 << 1)
#define DF_LANLINK2     (1 << 2)
#define DF_LANLINK3     (1 << 3)
#define DF_LANLINK4     (1 << 4)
#define DF_WANBOUND     (1 << 5)
#define DF_LANBOUND     (1 << 6)
#define DF_IPADDRDUP    (1 << 7)
#define DF_UPLOADING    (1 << 8)
#define DF_SOFTRESET    (1 << 9)
//#define DF_FXSUNUSABLE  (1 << 10)
#define DF_IGMPQUERYRCV (1 << 11)   /* Only available in bridge mode */
#define DF_NTPSYNC	(1 << 12)
#define DF_INITED	(1 << 13)
#define DF_RSTASSERTED  (1 << 14)
#define DF_WLCLNT_UP	(1 << 15) /* APACRTL-94 */

#ifdef __KERNEL__
unsigned int dvflag_set(unsigned int setbits, unsigned int mask);
unsigned int dvflag_get(void);
#endif

static inline int test_any_bit(unsigned int mask, unsigned int value)
{
	return (mask & value) != 0;
}

static inline int test_all_bits(unsigned int mask, unsigned int value)
{
	return ((mask & value) ^ mask) == 0;
}

static inline int test_inverted_set(unsigned int mask, unsigned int old, unsigned int new)
{
	return ((old ^ new) & (mask & new)) != 0;
}

static inline int test_inverted_clear(unsigned int mask, unsigned int old, unsigned int new)
{
	return ((old ^ new) & (mask & old)) != 0;
}

#endif /* __DVFLAG_H */
