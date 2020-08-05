// nvram_private.h

#ifndef __NVRAM_PRIVATE_H
#define __NVRAM_PRIVATE_H

#include <stdint.h>
#include <limits.h>
#include <byteswap.h>
#include <endian.h>

#if defined(__BYTE_ORDER) && __BYTE_ORDER == __BIG_ENDIAN
# define PF_BIG_ENDIAN 1
# define PF_LITTLE_ENDIAN 0
#elif defined(__BYTE_ORDER) && __BYTE_ORDER == __LITTLE_ENDIAN
# define PF_BIG_ENDIAN 0
# define PF_LITTLE_ENDIAN 1
#elif defined(_BYTE_ORDER) && _BYTE_ORDER == _BIG_ENDIAN
# define PF_BIG_ENDIAN 1
# define PF_LITTLE_ENDIAN 0
#elif defined(_BYTE_ORDER) && _BYTE_ORDER == _LITTLE_ENDIAN
# define PF_BIG_ENDIAN 0
# define PF_LITTLE_ENDIAN 1
#elif defined(BYTE_ORDER) && BYTE_ORDER == BIG_ENDIAN
# define PF_BIG_ENDIAN 1
# define PF_LITTLE_ENDIAN 0
#elif defined(BYTE_ORDER) && BYTE_ORDER == LITTLE_ENDIAN
# define PF_BIG_ENDIAN 0
# define PF_LITTLE_ENDIAN 1
#elif defined(__386__)
# define PF_BIG_ENDIAN 0
# define PF_LITTLE_ENDIAN 1
#else
# error "Can't determine endianness"
#endif

#if PF_BIG_ENDIAN
# define SWAP_BE16(x) (x)
# define SWAP_BE32(x) (x)
# define SWAP_BE64(x) (x)
# define SWAP_LE16(x) bswap_16(x)
# define SWAP_LE32(x) bswap_32(x)
# define SWAP_LE64(x) bb_bswap_64(x)
# define IF_BIG_ENDIAN(...) __VA_ARGS__
# define IF_LITTLE_ENDIAN(...)
#else
# define SWAP_BE16(x) bswap_16(x)
# define SWAP_BE32(x) bswap_32(x)
# define SWAP_BE64(x) bb_bswap_64(x)
# define SWAP_LE16(x) (x)
# define SWAP_LE32(x) (x)
# define SWAP_LE64(x) (x)
# define IF_BIG_ENDIAN(...)
# define IF_LITTLE_ENDIAN(...) __VA_ARGS__
#endif

#define __stringify_1(x...)	#x
#define __stringify(x...)	__stringify_1(x)

#if PF_BIG_ENDIAN
# define NVRAM_FILE_MAGIC 0x6e766733
#else
# define NVRAM_FILE_MAGIC 0x3367766e
#endif

#if !STORE_BIN2MTD
#define NVRAM_FILE_NAME "/tmp/ncp"
#define NVRAM_BAK_NAME "/tmp/ncb"
#endif

struct nvram_signature {
	unsigned int magic;			/* big endian */
	union {
		unsigned int inflate_size;	/* big endian */
		int version;
	};
};

#define nv_magic_sz sizeof(struct nvram_signature)

#define KB * 1024
#define MB * 1024 * 1024
#define _countof(x) (sizeof(x) / sizeof((x)[0]))

#ifndef TEMP_FAILURE_RETRY
#define TEMP_FAILURE_RETRY(expression)	\
	(__extension__			\
	({ int __result;				\
	do __result = (int)(expression);		\
	while (__result == -1L && errno == EINTR);	\
	__result; }))
#endif

enum {
	NVRAM_ERR_OK = 0,
	NVRAM_ERR_SYS = -1,
	NVRAM_ERR_NOFILE = -2,
	NVRAM_ERR_DECRYPT = -3,
	NVRAM_ERR_TOOBIG = -4,
	NVRAM_ERR_LENGTH = -5,
	NVRAM_ERR_INFLATE = -6,
	NVRAM_ERR_DEFLATE = -7,
};

#ifndef uninitialized_var
#define uninitialized_var(x) x = x
#endif
#endif	/* __NVRAM_PRIVATE_H */
