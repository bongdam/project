#define TYPEDEF_BOOL
#include <typedefs.h>
#include <bcmdefs.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/slab.h>

#include <bcmutils.h>
#include <bcmendian.h>
#include <bcmnvram.h>

#undef malloc
#undef free
extern void *malloc(uint32 nbytes);
extern void free(void *ap);
extern unsigned int flash_capacity;

struct nvram_variable {
	struct list_head list;
	char *string;
};

#define FLASH_MEM_MAP_ADDR 0xB0000000

#define KB * 1024
#define MB * 1024 * 1024

off_t p_nvram_offset;
off_t b_nvram_offset;
const int max_nvram_space = MAX_NVRAM_SPACE;

static LIST_HEAD(nvram_chain);

char *nvram_get(const char *name)
{
	struct list_head *p;
	size_t len;

	if (!name || (len = strlen(name)) == 0)
		return NULL;

	list_for_each(p, &nvram_chain) {
		struct nvram_variable *t = list_entry(p, struct nvram_variable, list);
		if (!strncmp(t->string, name, len) && t->string[len] == '=')
			return &t->string[len + 1];
	}

	return NULL;
}

int nvram_put(char *s)
{
	struct list_head *p;
	struct nvram_variable *t;
	char *q;
	int len;

	if (!s || !s[0])
		return -1;

	q = strchr(s, '=');
	if (!q)
		return -2;
	len = (int)(q - s);
	list_for_each(p, &nvram_chain) {
		t = list_entry(p, struct nvram_variable, list);
		if (!strncmp(t->string, s, len) && t->string[len] == '=') {
			if (strcmp(t->string, s)) {
				q = (char *)malloc(strlen(s) + 1);
				if (q == NULL)
					return -3;
				strcpy(q, s);
				free(t->string);
				t->string = q;
			}
			return 0;
		}
	}

	t = malloc(sizeof(struct nvram_variable));
	if (t == NULL)
		return -3;
	t->string = (char *)malloc(strlen(s) + 1);
	if (t->string == NULL) {
		free(t);
		return -3;
	}
	strcpy(t->string, s);
	list_add_tail(&t->list, &nvram_chain);
	return 0;
}

static void *_nvram_memcpy(void *dst, off_t off, int len)
{
	uint32 *d = (uint32 *)dst;
	char *dp;
	volatile uint32 *s = (volatile uint32 *)KSEG1ADDR(FLASH_MEM_MAP_ADDR + off);
	volatile char *sp;
	int i, len4;

	if ((((uint32)dst | off) & 3) == 0)
		for (i = 0, len4 = len & ~3; i < len4; i += 4)
			*d++ = *s++;

	for (dp = (char *)d, sp = (volatile char *)s; i < len; i++)
		*dp++ = *sp++;
	return dst;
}

static int _nvram_read(struct nvram_header *header)
{
	char *name, *end;

	name = (char *)&header[1];
	end = (char *)header + header->len;
	for (; *name && name < end; name += (strlen(name) + 1))
		if (nvram_put(name) < -1)
			return -1;
	return 0;
}

static int nvram_read(off_t pos)
{
	volatile struct nvram_header *header =
		(volatile struct nvram_header *)KSEG1ADDR(FLASH_MEM_MAP_ADDR + pos);
	char *buf;
	int res;

	buf = malloc(header->len);
	if (buf == NULL)
		return -1;
	(void)_nvram_memcpy(buf, pos, header->len);
	res = _nvram_read((struct nvram_header *)buf);
	free(buf);
	return res;
}

static off_t _find_nvram(uint32 magic, unsigned int flash_size, uint32 backoff)
{
	volatile struct nvram_header *header;
	uint32 off;

	for (off = flash_size; off >= 2 MB; off >>= 1) {
		header = (volatile struct nvram_header *)KSEG1ADDR(FLASH_MEM_MAP_ADDR + off - backoff);
		if (header->magic == magic && header->len <= MAX_NVRAM_SPACE)
			return (off - backoff);
	}
	return 0;
}

/*
                                                              Relocating Primary
        If the primary area was broken and there were         +----------------+
        the old & intact located at the half-backwarded       |                |
        address, the broken primary would be recovered        ~                ~
        from it till now.                                     |                |
        For the better, if the adjacent secondary were        |                |
        found intact, select it above all.                    |HSLF *oldies*   |--+
                                                           >  +----------------+  |
                                                          /   |                |  |
           Noraml         -> Broken The Primary          /    ~                ~  ~ Recover from *oldies*
  Beg  +----------------+    +----------------+         /     |                |  |
       |                |    |                |        /      |HSLB            |  |
       ~                ~    ~                ~       /       |HSLF *oldies*   |<-+
       |                |    |                |      /        +----------------+
       |                |    |                |     /
       |HSLF            |    |HSLF            |    /          if Secondary valid
  1/2  +----------------+    +----------------+  -+           Recover Primary
       |                |    |                |    \          from it
       ~                ~    ~                ~     \         +----------------+
       |                |    |                |      \        |                |
       |HSLB            |    |HSLB            |   better      ~                ~
       |HSLF            |    |   $corrupted$  |       way     |                |
  End  +----------------+    +----------------+         \     |                |
                                                         \    |HSLF *oldies*   |
                                                          \   +----------------+
                                                           \  |                |
                                                            > ~                ~
                                                              |                |
                                                              |HSLB *intact*   |--+
                                                              |HSLF *intact*   |<-+ Recover from *intact*
                                                              +----------------+
 */
int init_nvram(unsigned int flash_size)
{
	b_nvram_offset = 0;
	p_nvram_offset = _find_nvram(NVRAM_MAGIC, flash_size, MAX_NVRAM_SPACE);
	if (p_nvram_offset) {
		if (p_nvram_offset != (flash_size - MAX_NVRAM_SPACE)) {
			b_nvram_offset = _find_nvram(NVRAM_MAGIC2, flash_size,
						(MAX_NVRAM_SPACE << 1));
			if (b_nvram_offset == (flash_size - (MAX_NVRAM_SPACE << 1)))
				p_nvram_offset = 0;
			else
				b_nvram_offset = 0;
		}
	} else
		b_nvram_offset = _find_nvram(NVRAM_MAGIC2, flash_size, (MAX_NVRAM_SPACE << 1));

	if (p_nvram_offset | b_nvram_offset) {
		nvram_read(p_nvram_offset ? p_nvram_offset : b_nvram_offset);
		return 0;
	}
	return -1;
}

static const unsigned char crc8_table[256] = {
    0x00, 0xF7, 0xB9, 0x4E, 0x25, 0xD2, 0x9C, 0x6B,
    0x4A, 0xBD, 0xF3, 0x04, 0x6F, 0x98, 0xD6, 0x21,
    0x94, 0x63, 0x2D, 0xDA, 0xB1, 0x46, 0x08, 0xFF,
    0xDE, 0x29, 0x67, 0x90, 0xFB, 0x0C, 0x42, 0xB5,
    0x7F, 0x88, 0xC6, 0x31, 0x5A, 0xAD, 0xE3, 0x14,
    0x35, 0xC2, 0x8C, 0x7B, 0x10, 0xE7, 0xA9, 0x5E,
    0xEB, 0x1C, 0x52, 0xA5, 0xCE, 0x39, 0x77, 0x80,
    0xA1, 0x56, 0x18, 0xEF, 0x84, 0x73, 0x3D, 0xCA,
    0xFE, 0x09, 0x47, 0xB0, 0xDB, 0x2C, 0x62, 0x95,
    0xB4, 0x43, 0x0D, 0xFA, 0x91, 0x66, 0x28, 0xDF,
    0x6A, 0x9D, 0xD3, 0x24, 0x4F, 0xB8, 0xF6, 0x01,
    0x20, 0xD7, 0x99, 0x6E, 0x05, 0xF2, 0xBC, 0x4B,
    0x81, 0x76, 0x38, 0xCF, 0xA4, 0x53, 0x1D, 0xEA,
    0xCB, 0x3C, 0x72, 0x85, 0xEE, 0x19, 0x57, 0xA0,
    0x15, 0xE2, 0xAC, 0x5B, 0x30, 0xC7, 0x89, 0x7E,
    0x5F, 0xA8, 0xE6, 0x11, 0x7A, 0x8D, 0xC3, 0x34,
    0xAB, 0x5C, 0x12, 0xE5, 0x8E, 0x79, 0x37, 0xC0,
    0xE1, 0x16, 0x58, 0xAF, 0xC4, 0x33, 0x7D, 0x8A,
    0x3F, 0xC8, 0x86, 0x71, 0x1A, 0xED, 0xA3, 0x54,
    0x75, 0x82, 0xCC, 0x3B, 0x50, 0xA7, 0xE9, 0x1E,
    0xD4, 0x23, 0x6D, 0x9A, 0xF1, 0x06, 0x48, 0xBF,
    0x9E, 0x69, 0x27, 0xD0, 0xBB, 0x4C, 0x02, 0xF5,
    0x40, 0xB7, 0xF9, 0x0E, 0x65, 0x92, 0xDC, 0x2B,
    0x0A, 0xFD, 0xB3, 0x44, 0x2F, 0xD8, 0x96, 0x61,
    0x55, 0xA2, 0xEC, 0x1B, 0x70, 0x87, 0xC9, 0x3E,
    0x1F, 0xE8, 0xA6, 0x51, 0x3A, 0xCD, 0x83, 0x74,
    0xC1, 0x36, 0x78, 0x8F, 0xE4, 0x13, 0x5D, 0xAA,
    0x8B, 0x7C, 0x32, 0xC5, 0xAE, 0x59, 0x17, 0xE0,
    0x2A, 0xDD, 0x93, 0x64, 0x0F, 0xF8, 0xB6, 0x41,
    0x60, 0x97, 0xD9, 0x2E, 0x45, 0xB2, 0xFC, 0x0B,
    0xBE, 0x49, 0x07, 0xF0, 0x9B, 0x6C, 0x22, 0xD5,
    0xF4, 0x03, 0x4D, 0xBA, 0xD1, 0x26, 0x68, 0x9F
};

#define CRC_INNER_LOOP(n, c, x) \
	(c) = ((c) >> 8) ^ crc##n##_table[((c) ^ (x)) & 0xff]

unsigned char hndcrc8(
	unsigned char *pdata,	/* pointer to array of data to process */
	unsigned int  nbytes,	/* number of input data bytes to process */
	unsigned char crc	/* either CRC8_INIT_VALUE or previous return value */
)
{
	/* hard code the crc loop instead of using CRC_INNER_LOOP macro
	 * to avoid the undefined and unnecessary (unsigned char >> 8) operation.
	 */
	while (nbytes-- > 0)
		crc = crc8_table[(crc ^ *pdata++) & 0xff];

	return crc;
}

uint8 nvram_calc_crc(struct nvram_header *nvh)
{
	struct nvram_header tmp;
	uint8 crc;

	/* Little-endian CRC8 over the last 11 bytes of the header */
	tmp.crc_ver_init = htol32((nvh->crc_ver_init & NVRAM_CRC_VER_MASK));
	tmp.config_refresh = htol32(nvh->config_refresh);
	tmp.config_ncdl = htol32(nvh->config_ncdl);

	crc = hndcrc8((uint8 *)&tmp + NVRAM_CRC_START_POSITION,
		sizeof(struct nvram_header) - NVRAM_CRC_START_POSITION,
		CRC8_INIT_VALUE);

	/* Continue CRC8 over data bytes */
	crc = hndcrc8((uint8 *)&nvh[1], nvh->len - sizeof(struct nvram_header), crc);
	return crc;
}

int nvram_commit(void)
{
	char *ptr, *end;
	struct nvram_header *header;
	struct list_head *p;

	header = (struct nvram_header *)malloc(DEF_NVRAM_SPACE);
	if (header == NULL)
		return -1;

	memset(header, 0, DEF_NVRAM_SPACE);
	header->magic = NVRAM_MAGIC;
	header->crc_ver_init = (NVRAM_VERSION << 8);
	header->config_refresh = 0;
	header->config_ncdl = 0;

	ptr = (char *)&header[1];
	end = (char *)header + DEF_NVRAM_SPACE - 2;
	list_for_each(p, &nvram_chain) {
		struct nvram_variable *t = list_entry(p, struct nvram_variable, list);
		if ((ptr + strlen(t->string) + 1) > end)
			break;
		ptr += SprintF(ptr, "%s", t->string) + 1;
	}
	ptr += 2;
	header->len = ((int)(ptr - (char *)header) + 3) & ~3;
	header->crc_ver_init |= nvram_calc_crc(header);
#ifdef SUPPORT_SPI_MIO_8198_8196C
	spi_flw_image_mio_8198(0, flash_capacity - MAX_NVRAM_SPACE, (unsigned char *)header, header->len);
#else
	spi_flw_image(0, flash_capacity - MAX_NVRAM_SPACE, (unsigned char *)header, header->len);
#endif
	free(header);
	return 0;
}

void nvram_show(void)
{
	struct list_head *p;

	list_for_each(p, &nvram_chain) {
		struct nvram_variable *t = list_entry(p, struct nvram_variable, list);
		dprintf("%s\n", t->string);
	}
}

int nvram_backup(void)
{
	struct nvram_header *p, *b;
	unsigned char *buf;
	int rc = -1;

	buf = (unsigned char *)malloc(MAX_NVRAM_SPACE + sizeof(struct nvram_header));
	if (buf == NULL)
		return -1;

	p = (struct nvram_header *)_nvram_memcpy(buf,
			flash_capacity - MAX_NVRAM_SPACE, sizeof(struct nvram_header));
	if (p->magic != NVRAM_MAGIC)
		return -1;
	b = (struct nvram_header *)_nvram_memcpy(&buf[MAX_NVRAM_SPACE],
			flash_capacity - (MAX_NVRAM_SPACE << 1), sizeof(struct nvram_header));

	if ((b->magic != NVRAM_MAGIC2) ||
	    (({ b->magic = NVRAM_MAGIC; 1;}) && memcmp(p, b, sizeof(struct nvram_header)))) {
		(void)_nvram_memcpy(&p[1],
				flash_capacity - MAX_NVRAM_SPACE + sizeof(struct nvram_header),
				p->len - sizeof(struct nvram_header));
		p->magic = NVRAM_MAGIC2;
#ifdef SUPPORT_SPI_MIO_8198_8196C
		spi_flw_image_mio_8198(0, flash_capacity - (MAX_NVRAM_SPACE << 1), buf, p->len);
#else
		spi_flw_image(0, flash_capacity - (MAX_NVRAM_SPACE << 1), buf, p->len);
#endif
		rc = 0;
	}
	free(buf);
	return rc;
}

int parse_bootline(unsigned int *kern, unsigned int *fs)
{
	char *q, *p = nvram_get("x_sys_bootm");

	if (p != NULL) {
		unsigned int kernel = strtoul(p, &q, 16);
		if (*q) {
			unsigned int rootfs = strtoul(++q, NULL, 16);
			if (kernel < rootfs && rootfs < flash_capacity) {
				*kern = kernel;
				*fs = rootfs;
				return 0;
			}
		}
	}

	return -1;
}
