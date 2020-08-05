// DAVO modified
/*
 * NVRAM variable manipulation
 *
 * Copyright (C) 2013, Broadcom Corporation. All Rights Reserved.
 * 
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * $Id: bcmnvram.h 401759 2013-05-13 16:08:08Z $
 */

#ifndef _bcmnvram_h_
#define _bcmnvram_h_

#ifndef _LANGUAGE_ASSEMBLY

#include <typedefs.h>
#include <bcmdefs.h>

struct nvram_header {
	uint32 magic;
	uint32 len;
	uint32 crc_ver_init;	/* 0:7 crc, 8:15 ver, 16:31 sdram_init */
	uint32 config_refresh;	/* 0:15 sdram_config, 16:31 sdram_refresh */
	uint32 config_ncdl;	/* ncdl values for memc */
};

struct nvram_tuple {
	char *name;
	char *value;
	struct nvram_tuple *next;
};

/*
 * Get default value for an NVRAM variable
 */
extern char *nvram_default_get(const char *name);
/*
 * validate/restore all per-interface related variables
 */
extern void nvram_validate_all(char *prefix, bool restore);

/*
 * restore specific per-interface variable
 */
extern void nvram_restore_var(char *prefix, char *name);

/*
 * Initialize NVRAM access. May be unnecessary or undefined on certain
 * platforms.
 */
extern int nvram_init(void *);
extern int nvram_deinit(void);

/*
 * Append a chunk of nvram variables to the global list
 */
extern int nvram_append(void *si, char *vars, uint varsz);

extern void nvram_get_global_vars(char **varlst, uint *varsz);


/*
 * Check for reset button press for restoring factory defaults.
 */
extern int nvram_reset(void *sih);

/*
 * Disable NVRAM access. May be unnecessary or undefined on certain
 * platforms.
 */
extern void nvram_exit(void *sih);

/*
 * Get the value of an NVRAM variable. The pointer returned may be
 * invalid after a set.
 * @param	name	name of variable to get
 * @return	value of variable or NULL if undefined
 */
extern char * nvram_get(const char *name);

/*
 * Get the value of an NVRAM variable.
 * @param	name	name of variable to get
 * @return	value of variable or NUL if undefined
 */
static INLINE char *
nvram_safe_get(const char *name)
{
	char *p = nvram_get(name);
	return p ? p : "";
}

/*
 * Match an NVRAM variable.
 * @param	name	name of variable to match
 * @param	match	value to compare against value of variable
 * @return	TRUE if variable is defined and its value is string equal
 *		to match or FALSE otherwise
 */
static INLINE int
nvram_match(const char *name, const char *match)
{
	const char *value = nvram_get(name);
	return (value && !strcmp(value, match));
}

/*
 * Inversely match an NVRAM variable.
 * @param	name	name of variable to match
 * @param	match	value to compare against value of variable
 * @return	TRUE if variable is defined and its value is not string
 *		equal to invmatch or FALSE otherwise
 */
static INLINE int
nvram_invmatch(const char *name, const char *invmatch)
{
	const char *value = nvram_get(name);
	return (value && strcmp(value, invmatch));
}

/*
 * Set the value of an NVRAM variable. The name and value strings are
 * copied into private storage. Pointers to previously set values
 * may become invalid. The new value may be immediately
 * retrieved but will not be permanently stored until a commit.
 * @param	name	name of variable to set
 * @param	value	value of variable
 * @return	0 on success and errno on failure
 */
extern int nvram_set(const char *name, const char *value);

/*
 * Unset an NVRAM variable. Pointers to previously set values
 * remain valid until a set.
 * @param	name	name of variable to unset
 * @return	0 on success and errno on failure
 * NOTE: use nvram_commit to commit this change to flash.
 */
extern int nvram_unset(const char *name);

/*
 * Commit NVRAM variables to permanent storage. All pointers to values
 * may be invalid after a commit.
 * NVRAM values are undefined after a commit.
 * @param   nvram_corrupt    true to corrupt nvram, false otherwise.
 * @return	0 on success and errno on failure
 */
extern int nvram_commit_internal(bool nvram_corrupt);

/*
 * Commit NVRAM variables to permanent storage. All pointers to values
 * may be invalid after a commit.
 * NVRAM values are undefined after a commit.
 * @return	0 on success and errno on failure
 */
extern int nvram_commit(void);

/*
 * Get all NVRAM variables (format name=value\0 ... \0\0).
 * @param	buf	buffer to store variables
 * @param	count	size of buffer in bytes
 * @return	0 on success and errno on failure
 */
extern int nvram_getall(char *nvram_buf, int count);

/*
 * returns the crc value of the nvram
 * @param	nvh	nvram header pointer
 */
uint8 nvram_calc_crc(struct nvram_header * nvh);

extern int nvram_space;

#if defined(__DAVO__) && !defined(__KERNEL__)
extern char *_nvram_get_r(char *name, char *buf, int bufsize, char *dfl);

#define nvram_get_r(name, buf, bufsize) _nvram_get_r(name, buf, bufsize, NULL)
#define nvram_get_r_def(name, buf, bufsize, dfl) (_nvram_get_r(name, buf, bufsize, dfl) ? : buf)
#define nvram_safe_get_r(name, buf, bufsize) _nvram_get_r(name, buf, bufsize, "")

#define nvram_match_r		nvram_match
#define nvram_invmatch_r	nvram_invmatch
#endif /* __DAVO && !__KERNEL__ */
#endif /* _LANGUAGE_ASSEMBLY */

/* The NVRAM version number stored as an NVRAM variable */
#define NVRAM_SOFTWARE_VERSION	"1"

#define NVRAM_MAGIC		0x48534C46	/* 'FLSH' */
#if defined(__DAVO__)
#define NVRAM_MAGIC2		0x48534C42	/* 'BLSH' */
#endif
#define NVRAM_CLEAR_MAGIC	0x0
#define NVRAM_INVALID_MAGIC	0xFFFFFFFF
#define NVRAM_VERSION		1
#define NVRAM_HEADER_SIZE	20
/* This definition is for precommit staging, and will be removed */
#define NVRAM_SPACE		0x10000		/* __DAVO__ */
/* For CFE builds this gets passed in thru the makefile */
#ifndef MAX_NVRAM_SPACE
#define MAX_NVRAM_SPACE		0x20000		/* __DAVO__ */
#endif
#define DEF_NVRAM_SPACE		0x20000		/* __DAVO__ */
#define ROM_ENVRAM_SPACE	0x1000
#define NVRAM_LZMA_MAGIC	0x4c5a4d41	/* 'LZMA' */

#define NVRAM_MAX_VALUE_LEN 255
#define NVRAM_MAX_PARAM_LEN 64

#define NVRAM_CRC_START_POSITION	9 /* magic, len, crc8 to be skipped */
#define NVRAM_CRC_VER_MASK	0xffffff00 /* for crc_ver_init */

/* Offsets to embedded nvram area */
#define NVRAM_START_COMPRESSED	0x400
#define NVRAM_START		0x1000

#define BCM_JUMBO_NVRAM_DELIMIT '\n'
#define BCM_JUMBO_START "Broadcom Jumbo Nvram file"

#endif /* _bcmnvram_h_ */
