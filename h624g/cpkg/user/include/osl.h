#ifndef _osl_h_
#define _osl_h_

#ifdef __KERNEL__
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/slab.h>

#define	printf(fmt, args...)	printk(fmt , ## args)
#define	bzero(b, len)		memset((b), '\0', (len))
#define malloc(s)		kmalloc((s), GFP_ATOMIC)
#define free(p)			kfree(p)
#else
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#endif
#endif
