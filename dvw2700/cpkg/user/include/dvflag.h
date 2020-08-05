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

#ifndef PRTNR_WAN0
# error PRTNR_WAN0 must be defined globally!
#endif

#define DF_WANLINK      (1 << PRTNR_WAN0)
#define DF_LANLINK1     (1 << PRTNR_LAN1)
#define DF_LANLINK2     (1 << PRTNR_LAN2)
#define DF_LANLINK3     (1 << PRTNR_LAN3)
#define DF_LANLINK4     (1 << PRTNR_LAN4)

#define DF_WANBOUND     (1 << PRTNR_MAX)
#define DF_LANBOUND     (1 << (PRTNR_MAX + 1))
#define DF_IPADDRDUP    (1 << (PRTNR_MAX + 2))
#define DF_UPLOADING    (1 << (PRTNR_MAX + 3))
#define DF_NTPSYNC	(1 << (PRTNR_MAX + 4))
#define DF_INITED	(1 << (PRTNR_MAX + 5))
#define DF_REBOOTING	(1 << (PRTNR_MAX + 6))
#define DF_RSTASSERTED	(1 << (PRTNR_MAX + 7))
#define DF_WPSASSERTED	(1 << (PRTNR_MAX + 8))
#define DF_WANIPFILE	(1 << (PRTNR_MAX + 9))

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

