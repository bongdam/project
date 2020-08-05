#ifndef _bcmnvram_h_
#define _bcmnvram_h_

#ifndef __KERNEL__
#include <sys/ioctl.h>
#include <string.h>
#include <stdlib.h>
#endif

struct nvram_header {
	u_int32_t magic;
	u_int32_t len;
	u_int32_t crc_ver_init;		/* 0:7 crc, 8:15 ver, 16:31 reserved */
	u_int32_t kern_start;
	u_int32_t rootfs_start;
};

/* The NVRAM version number stored as an NVRAM variable */
#define NVRAM_SOFTWARE_VERSION	"1"

#define NVRAM_MAGIC		0x48534c46	/* 'FLSH' */
#define NVRAM_MAGIC2		0x48534c42	/* 'BLSH' */

#define NVRAM_CLEAR_MAGIC	0x0
#define NVRAM_INVALID_MAGIC	0xffffffff
#define NVRAM_VERSION		1
#define NVRAM_HEADER_SIZE	20
/* This definition is for precommit staging, and will be removed */
#define NVRAM_SPACE		0x20000
/* For CFE builds this gets passed in thru the makefile */
#define MAX_NVRAM_SPACE		NVRAM_SPACE
#define DEF_NVRAM_SPACE		NVRAM_SPACE

#define NVRAM_MAX_VALUE_LEN	255
#define NVRAM_MAX_PARAM_LEN	64

#define NVRAM_CRC_START_POSITION 9	/* magic, len, crc8 to be skipped */
#define NVRAM_CRC_VER_MASK 0xffffff00	/* for crc_ver_init */
#define CRC8_INIT_VALUE 0xff		/* Initial CRC8 checksum value */
#define CRC8_GOOD_VALUE 0x9f		/* Good final CRC8 checksum value */

struct nvreq {
	char *sptr;
	int length;
};

#define NVRAM_IOTYPE 'Y'

enum {
	__NVRAM_CMD_GET = 0xa0,
	__NVRAM_CMD_SET,
};

#define NVRAM_CMD_GET _IOR(NVRAM_IOTYPE, __NVRAM_CMD_GET, struct nvreq)
#define NVRAM_CMD_SET _IOW(NVRAM_IOTYPE, __NVRAM_CMD_SET, struct nvreq)

#ifndef __KERNEL__
extern char *nvram_get(const char *name);
extern int nvram_set(const char *name, const char *value);
extern int nvram_unset(const char *name);
extern int nvram_commit(void);
extern int nvram_getall(char *nvram_buf, int count);
extern char *_nvram_get_r(char *name, char *buf, int bufsize, char *dfl);

extern int nvram_sha_256_set(const char *name, const char *value);
extern int nvram_sha_512_set(const char *name, const char *value);

/* return zero if matched */
extern int nvram_sha_256_cmp(const char *name, const char *plain);
extern int nvram_sha_512_cmp(const char *name, const char *plain);

extern int nvram_aes_cbc_set(const char *name, const char *value);
extern int nvram_aes_cbc_get(const char *name, char *buf, unsigned int size);

static inline char *nvram_safe_get(const char *name)
{
	char *p = nvram_get(name);
	return p ? p : "";
}

static inline int nvram_match(const char *name, const char *match)
{
	const char *value = nvram_get(name);
	return (value && !strcmp(value, match));
}

static inline int nvram_invmatch(const char *name, const char *invmatch)
{
	const char *value = nvram_get(name);
	return (value && strcmp(value, invmatch));
}

static inline int nvram_get_int(const char *name, int def_val)
{
	char *p = nvram_get(name);
	return p ? (int)strtol(p, NULL, 0):def_val;
}

#define nvram_get_r(name, buf, bufsize) _nvram_get_r(name, buf, bufsize, NULL)
#define nvram_get_r_def(name, buf, bufsize, dfl) (_nvram_get_r(name, buf, bufsize, dfl) ? : buf)
#define nvram_safe_get_r(name, buf, bufsize) _nvram_get_r(name, buf, bufsize, "")
#define nvram_match_r nvram_match
#define nvram_invmatch_r nvram_invmatch

#endif /* !__KERNEL__ */

#endif
