#ifndef WPAS_GLUE_H
#define WPAS_GLUE_H

#include <linux/slab.h>
#include <linux/string.h>

/* Copied from wpa_debug.h */
enum {
	MSG_EXCESSIVE, MSG_MSGDUMP, MSG_DEBUG, MSG_INFO, MSG_WARNING, MSG_ERROR
};

//extern void   _rtw_memset(void *pbuf, int c, u32 sz);
static void os_memset(void *s, int c, size_t n)
{
	memset(s, c, n);
}

//extern void   _rtw_memcpy(void *dec, const void *sour, u32 sz);
static void os_memcpy(void *dest, const void *src, size_t n)
{
	memcpy(dest, src, n);
}

static void wpa_hexdump_key(int level, const char *title, const void *buf, size_t len)
{
	/* TODO */
}

static void wpa_hexdump(int level, const char *title, const void *buf, size_t len)
{
	/* TODO */
}

/* Copied from os_internal.c */
static int os_memcmp_const(const void *a, const void *b, size_t len)
{
	const u8 *aa = a;
	const u8 *bb = b;
	size_t i;
	u8 res;

	for (res = 0, i = 0; i < len; i++)
		res |= aa[i] ^ bb[i];

	return res;
}

static void wpa_printf(int level, const char *fmt, ...)
{
	/* TODO */
}

static void *os_malloc(size_t size)
{
	u8 *pbuf = NULL;

	pbuf = kmalloc(size, /*GFP_KERNEL */ GFP_ATOMIC);

	return pbuf;
}

static void os_free(void *ptr)
{
	if (ptr)
		kfree(ptr);

}

/* Copied from ieee802_11_defs.h */
#define WLAN_FC_PVER		0x0003
#define WLAN_FC_TODS		0x0100
#define WLAN_FC_FROMDS		0x0200
#define WLAN_FC_MOREFRAG	0x0400
#define WLAN_FC_RETRY		0x0800
#define WLAN_FC_PWRMGT		0x1000
#define WLAN_FC_MOREDATA	0x2000
#define WLAN_FC_ISWEP		0x4000
#define WLAN_FC_ORDER		0x8000

#define WLAN_FC_GET_TYPE(fc)	(((fc) & 0x000c) >> 2)
#define WLAN_FC_GET_STYPE(fc)	(((fc) & 0x00f0) >> 4)

#define WLAN_INVALID_MGMT_SEQ   0xFFFF

#define WLAN_GET_SEQ_FRAG(seq) ((seq) & (BIT(3) | BIT(2) | BIT(1) | BIT(0)))
#define WLAN_GET_SEQ_SEQ(seq) \
	(((seq) & (~(BIT(3) | BIT(2) | BIT(1) | BIT(0)))) >> 4)

#define WLAN_FC_TYPE_MGMT		0
#define WLAN_FC_TYPE_CTRL		1
#define WLAN_FC_TYPE_DATA		2

#endif				/* WPAS_GLUE_H */
