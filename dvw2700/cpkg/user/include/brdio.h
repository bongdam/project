/* miscellaneous board IO */

#ifndef __BRDIO_H
#define __BRDIO_H

#define BRDIO_MAJOR		210     /* arbitrary unused value */

enum {
	__PHGIO = 0xa0,	/* PHY IO command */
	__PHSIO,
	__PVIDGET,
	__BIOCGETHRX,
	__BIOCSETHCLRRX,
	__GPIOCOUT,	/* configure as OUTPUT */
	__GPIOCIN,	/* configure as INPUT */
	__GPIOSHOUT,	/* write HI */
	__GPIOSLOUT,	/* write LO */
	__GPIOGIN,	/* read */

	__GPIOSACTIVE,	/* activate */
	__GPIOSINACT,	/* inactivate */
	__GPIOGACTIVE,	/* query activity */
	__GPIODECONF,	/* de-configiure */
	__PSTATUS		/* APACTL-522 Get port status */
};

#define PHGIO _IO(BRDIO_MAJOR, __PHGIO)
#define PHSIO _IO(BRDIO_MAJOR, __PHSIO)
#define PVIDGET _IO(BRDIO_MAJOR, __PVIDGET)
#define BIOCGETHRX _IO(BRDIO_MAJOR, __BIOCGETHRX)
#define BIOCSETHCLRRX _IO(BRDIO_MAJOR, __BIOCSETHCLRRX)
#define GPIOCOUT _IO(BRDIO_MAJOR, __GPIOCOUT)
#define GPIOCIN _IO(BRDIO_MAJOR, __GPIOCIN)
#define GPIOSHOUT _IO(BRDIO_MAJOR, __GPIOSHOUT)
#define GPIOSLOUT _IO(BRDIO_MAJOR, __GPIOSLOUT)
#define GPIOGIN _IO(BRDIO_MAJOR, __GPIOGIN)
#define GPIODECFG _IO(BRDIO_MAJOR, __GPIODECONF)

/* PHY configuration */
#define PH_MINPORT      0
#define PH_MAXPORT      4

#define PHF_PWRUP       0x01
#define PHF_LINKUP      PHF_PWRUP
#define PHF_AUTONEG     0x02
#define PHF_FDX         0x04
#define PHF_10M         0x08
#define PHF_100M        0x10
#define PHF_500M        0x20
#define PHF_1000M       0x40
#define PHF_RXPAUSE     0x80
#define PHF_TXPAUSE     0x100
#define PHF_RESET       PHF_AUTONEG
#define PHF_EEE         0x400
#define PHF_ENFORCE_POLL       0x800
#define PHF_ENFORCE_NO_AUTONEG 0x1000
#define PHF_OVERWREG    0x10000

#define PHF_PWRDOWN		0x20000

#define PHF_SPEEDMASK   (PHF_10M | PHF_100M | PHF_500M | PHF_1000M)

/* PHY configuration request */
struct phreq {
	int phr_port;
	unsigned int phr_option;
	unsigned int phr_optmask;
};

struct stats_ether {
	unsigned long long rx_bytes	__attribute__ ((aligned(16)));
	unsigned long long rx_packets;
};

#ifdef __KERNEL__
extern int sys_gpio_operate(int cmd, const char *name, unsigned int *value);
#endif
#endif
