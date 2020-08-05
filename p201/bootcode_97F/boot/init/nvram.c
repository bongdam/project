#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <bcmnvram.h>
#include "utility.h"

#undef malloc
#undef free
extern void *malloc(u_int32_t nbytes);
extern void free(void *ap);

#define FLASH_MEM_MAP_ADDR 0xB0000000

#define KB * 1024
#define MB * 1024 * 1024

unsigned int flash_capacity;

static void *_nvram_memcpy(void *dst, off_t off, int len)
{
	u_int32_t *d = (u_int32_t *)dst;
	char *dp;
	volatile u_int32_t *s = (volatile u_int32_t *)KSEG1ADDR(FLASH_MEM_MAP_ADDR + off);
	volatile char *sp;
	int i = 0, len4;

	if ((((u_int32_t)dst | off) & 3) == 0)
		for (i = 0, len4 = len & ~3; i < len4; i += 4)
			*d++ = *s++;

	for (dp = (char *)d, sp = (volatile char *)s; i < len; i++)
		*dp++ = *sp++;
	return dst;
}

static int nvram_copy(off_t to, off_t from, u_int32_t magic)
{
	struct nvram_header *p;

	p = (struct nvram_header *)malloc(MAX_NVRAM_SPACE);
	if (p == NULL)
		return -1;
	_nvram_memcpy(p, from, sizeof(*p));
	_nvram_memcpy(&p[1], from + sizeof(*p), p->len - sizeof(*p));

	p->magic = magic;
#ifdef SUPPORT_SPI_MIO_8198_8196C
	spi_flw_image_mio_8198(0, to, (unsigned char *)p, p->len);
#else
	spi_flw_image(0, to, (unsigned char *)p, p->len);
#endif
	free(p);
	return 0;
}

static unsigned char crc8(unsigned char *pdata, int len, unsigned char crc)
{
	int i;

	while (len-- > 0) {
		crc = crc ^ *pdata++;
		for (i = 0; i < 8; i++) {
			if ((crc & 1)) {
				crc >>= 1;
				crc ^= 0xab;
			} else
				crc >>= 1;
		}
	}
	return crc;
}

static u_int8_t nvram_calc_crc(struct nvram_header *h, void *buf, ssize_t count)
{
	struct nvram_header tmp;
	u_int8_t crc;

	/* Little-endian CRC8 over the last 11 bytes of the header */
	tmp.crc_ver_init = htonl((h->crc_ver_init & NVRAM_CRC_VER_MASK));
	tmp.kern_start = htonl(h->kern_start);
	tmp.rootfs_start = htonl(h->rootfs_start);

	crc = crc8((u_int8_t *)&tmp + NVRAM_CRC_START_POSITION,
		sizeof(struct nvram_header) - NVRAM_CRC_START_POSITION,
		CRC8_INIT_VALUE);

	/* Continue CRC8 over data bytes */
	return crc8((u_int8_t *)buf, count, crc);
}

static off_t
_find_nvram(u_int32_t magic, u_int32_t flash_capacity, u_int32_t backoff, struct nvram_header *h)
{
	u_int32_t off, loc = 0;
	char *buf;

	for (off = flash_capacity; !loc && off >= 2 MB; off >>= 1) {
		_nvram_memcpy(h, off - backoff, sizeof(*h));
		if (h->magic != magic || h->len > MAX_NVRAM_SPACE)
			continue;
		buf = malloc(h->len - sizeof(*h));
		if (buf == NULL)
			break;
		_nvram_memcpy(buf, off - backoff + sizeof(*h), h->len - sizeof(*h));
		if (nvram_calc_crc(h, buf, h->len - sizeof(*h)) == (u_int8_t)h->crc_ver_init)
			loc = off - backoff;
		free(buf);
	}
	return loc;
}

enum {
	NPGS = 1,	/* No Primary Good Secondary */
	NPAS,		/* No Primary Alternate Secondary */
	APNS,		/* Alternate Primary No Secondary */
	APAS,		/* Alternate Primary Alternate Secondary */
	APGS,		/* Alternate Primary Good Secondary */
	GPNS,		/* Good Primary No Secondary */
	GPAS,		/* Good Primary Alternate Secondary */
	GPGS,		/* Good Primary Good Secondary But Different */
};

int nvram_coincide(SETTING_HEADER_Tp p)
{
	off_t prioff, secoff;
	struct nvram_header F, B;
	int state = 0;

	prioff = _find_nvram(NVRAM_MAGIC, flash_capacity, MAX_NVRAM_SPACE, &F);
	secoff = _find_nvram(NVRAM_MAGIC2, flash_capacity, (MAX_NVRAM_SPACE << 1), &B);
	if (!prioff) {
		if (!secoff)
			return -1;
		else if (secoff == (flash_capacity - (MAX_NVRAM_SPACE << 1)))
			state = NPGS;
		else
			state = NPAS;
	} else if (prioff != (flash_capacity - MAX_NVRAM_SPACE)) {
		if (secoff != (flash_capacity - (MAX_NVRAM_SPACE << 1)))
			state = secoff ? APAS : APNS;
		else
			state = APGS;
	} else if (secoff != (flash_capacity - (MAX_NVRAM_SPACE << 1)))
		state = secoff ? GPAS : GPNS;
	else if (memcmp(((char *)&F) + sizeof(F.magic), ((char *)&B) + sizeof(F.magic), sizeof(F) - sizeof(F.magic)))
		state = GPGS;

	switch (state) {
	case NPGS:
	case APGS:
		nvram_copy(flash_capacity - MAX_NVRAM_SPACE, secoff, NVRAM_MAGIC); // B > P
		break;
	case NPAS:
		nvram_copy(flash_capacity - MAX_NVRAM_SPACE, secoff, NVRAM_MAGIC);	// B' > P > B
		nvram_copy(flash_capacity - (MAX_NVRAM_SPACE << 1), flash_capacity - MAX_NVRAM_SPACE, NVRAM_MAGIC2);
		break;
	case APNS:
	case APAS:
		nvram_copy(flash_capacity - MAX_NVRAM_SPACE, prioff, NVRAM_MAGIC);
		nvram_copy(flash_capacity - (MAX_NVRAM_SPACE << 1), flash_capacity - MAX_NVRAM_SPACE, NVRAM_MAGIC2);
		break;
	case GPNS:
	case GPAS:
	case GPGS:
		nvram_copy(flash_capacity - (MAX_NVRAM_SPACE << 1), prioff, NVRAM_MAGIC2); // P > B
		break;
	default:
		break;
	}

	if (state)
		_nvram_memcpy(&F, flash_capacity - MAX_NVRAM_SPACE, sizeof(F));
	p->kern_offset = F.kern_start;
	p->root_offset = F.rootfs_start;

	switch (state) {
	case NPGS:
	case APGS:
		dprintf("\nNVRAM recovered from the Secondary!\n");
		break;
	case NPAS:
	case APNS:
	case APAS:
		dprintf("\nNVRAM relocated(%d)\n", state);
		break;
	case GPNS:
	case GPAS:
	case GPGS:
		dprintf("\nNVRAM copied to the Secondary!\n");
		break;
	default:
		break;
	}
	return state;
}

int nvram_update_bootline(unsigned int kern_off, unsigned int fs_off)
{
	struct nvram_header h, *p;
	char *buf;

	_nvram_memcpy(&h, flash_capacity - MAX_NVRAM_SPACE, sizeof(h));
	if (h.len > MAX_NVRAM_SPACE || !(buf = malloc(h.len)))
		return -1;
	p = _nvram_memcpy(buf, flash_capacity - MAX_NVRAM_SPACE, h.len);
	p->kern_start = kern_off;
	p->rootfs_start = fs_off;
	p->crc_ver_init &= ~0xff;
	p->crc_ver_init |= nvram_calc_crc(p, (void *)(p + 1), p->len - sizeof(struct nvram_header));
#ifdef SUPPORT_SPI_MIO_8198_8196C
	spi_flw_image_mio_8198(0, flash_capacity - MAX_NVRAM_SPACE, (unsigned char *)p, p->len);
#else
	spi_flw_image(0, flash_capacity - MAX_NVRAM_SPACE, (unsigned char *)p, p->len);
#endif
	free(buf);
	return nvram_copy(flash_capacity - (MAX_NVRAM_SPACE << 1), flash_capacity - MAX_NVRAM_SPACE, NVRAM_MAGIC2);
}
