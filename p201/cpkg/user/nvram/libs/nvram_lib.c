#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <error.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <fcntl.h>
#include <search.h>
#include <pthread.h>

#include <bcmnvram.h>
#include <signal.h>
#include "nvram_private.h"
#include "crypto_linux.h"

#define PATH_DEV_NVRAM "/dev/nvram"

union semun {
	int val;		/* Value for SETVAL */
	struct semid_ds *buf;	/* Buffer for IPC_STAT, IPC_SET */
	unsigned short  *array;	/* Array for GETALL, SETALL */
	struct seminfo  *__buf;	/* Buffer for IPC_INFO (Linux-specific) */
};

enum {
        MuTEX = 1,
        NuMSEM
};

static int nvram_fd = -1;
static int nvram_sema = -1;	// ipc semaphore id
static struct sembuf SMup[] = { {MuTEX, -1, IPC_NOWAIT | SEM_UNDO} };
static struct sembuf SMdn[] = { {0, 0}, {MuTEX, 0}, {MuTEX, +1, SEM_UNDO} };

static char *nvram_user_get(const char *name, char *value);
extern int nvram_store(void *src, size_t size);
extern char *nvram_aes_cbc_enc(const char *in, unsigned int *len);
extern char *nvram_aes_cbc_dec(const char *in, unsigned int *len);

static inline int nvram_lib_lock(void)
{
	return (nvram_sema > -1) ?
	       TEMP_FAILURE_RETRY(semop(nvram_sema, SMdn, _countof(SMdn))) : -1;
}

static inline void nvram_lib_unlock(int flg)
{
	if (nvram_sema > -1 && !flg)
		TEMP_FAILURE_RETRY(semop(nvram_sema, SMup, _countof(SMup)));
}

static int nvram_init_MUTEX(key_t k)
{
	union semun arg = { .val = 0 };
	int id;

	id = semget(k, NuMSEM, 0);
	if (id < 0 && errno == ENOENT) {
		if ((id = semget(k, NuMSEM, IPC_CREAT | IPC_EXCL | 0600)) < 0) {
			if (errno != EEXIST || ((id = semget(k, NuMSEM, 0))) < 0)
				return -1;
		}
		semctl(id, NuMSEM, SETVAL, arg);
	}

	return id;
}

static int nvram_init(void)
{
	if (nvram_fd < 0) {
		int fd = open(PATH_DEV_NVRAM, O_RDWR);
		if (fd != -1) {
			fcntl(fd, F_SETFD, FD_CLOEXEC);
			nvram_sema = nvram_init_MUTEX(ftok("/bin/true", 'v'));
			if (nvram_sema < 0)
				close(fd);
			else
				nvram_fd = fd;
		}
	}
	return (nvram_fd > -1) ? 0 : -1;
}

typedef struct {
	const char *s;
	int len;
} str;

#define TRIM_SWITCH(c) \
	switch(c) { \
	case ' ': \
	case '\t': \
	case '\r': \
	case '\n': \
		break; \
	default: \
		return; \
	}

static inline void trim_leading(str * _s)
{
	for (; _s->len > 0; _s->len--, _s->s++) {
		TRIM_SWITCH(*(_s->s));
	}
}

static inline void trim_trailing(str * _s)
{
	for (; _s->len > 0; _s->len--) {
		TRIM_SWITCH(_s->s[_s->len - 1]);
	}
}

static inline void trim_whites(str * _s)
{
	trim_leading(_s);
	trim_trailing(_s);
}

static int strim(str *_s, const char *s)
{
	_s->s = s;
	_s->len = s ? (int)strlen(s) : 0;
	trim_whites(_s);
	return _s->len;
}

static char *slcpy(char *dst, const char *src, size_t size)
{
	if (dst && src)
		*stpncpy(dst, src, size) = '\0';
	return dst;
}

char *nvram_get(const char *name)
{
	str name_s;
	ssize_t count;
	char *value = NULL;
	struct nvreq req;
	int errnum = 0;

	if (nvram_init())
		return NULL;

	if (strim(&name_s, name) == 0)
		return NULL;

	count = ((name_s.len + 63) & ~63) + 128;
	req.sptr = slcpy(alloca(count), name_s.s, name_s.len);
	req.length = count;

	if (ioctl(nvram_fd, NVRAM_CMD_GET, &req))
		errnum = errno;
	else if (count <= req.length) {
		req.length += 1;
		req.sptr = slcpy(alloca(req.length), name_s.s, name_s.len);
		if (ioctl(nvram_fd, NVRAM_CMD_GET, &req))
			errnum = errno;
	}

	if (!errnum)	// it's OK
		value = nvram_user_get(slcpy(alloca(name_s.len + 1), name_s.s, name_s.len), req.sptr);
	else if (errnum != ENOENT)
		fprintf(stderr, "%s: %s\n", PATH_DEV_NVRAM, strerror(errnum));

	return value;
}

static int _nvram_getall(char *buf, int count, int commit)
{
	sigset_t sigset, oldset;
	struct nvreq req;
	int ret, flag;

	if (nvram_init())
		return -1;
	else if (count == 0)
		return 0;

	if (count > (MAX_NVRAM_SPACE - NVRAM_HEADER_SIZE))
		count = MAX_NVRAM_SPACE - NVRAM_HEADER_SIZE;

	/* Get all variables */
	*buf = '\0';
	req.sptr = buf;
	req.length = count;

	sigfillset(&sigset);
	sigprocmask(SIG_BLOCK, &sigset, &oldset);

	flag = nvram_lib_lock();
	ret = ioctl(nvram_fd, NVRAM_CMD_GET, &req);
	if (ret == 0 && commit) {
		if (req.length >= count)
			req.length = ((char *)memrchr(buf, '\0', count) - buf) + 1;
		ret = nvram_store(buf, req.length);
	}
	nvram_lib_unlock(flag);

	sigprocmask(SIG_SETMASK, &oldset, NULL);

	return ret;
}

int nvram_getall(char *buf, int count)
{
	return _nvram_getall(buf, count, 0);
}

static int _nvram_set(str *name, str *value)
{
	char tmp[100], *buf = tmp, *p;
	size_t count;
	int ret;
	struct nvreq req;

	count = (size_t)name->len + 1;
	if (value)
		count += (value->len + 1);

	if (count > sizeof(tmp) && !(buf = malloc(count)))
		return -1;

	if (value)
		sprintf(buf, "%.*s=%.*s", name->len, name->s, value->len, value->s);
	else
		sprintf(buf, "%.*s", name->len, name->s);

	req.sptr = buf;
	req.length = count;

	ret = ioctl(nvram_fd, NVRAM_CMD_SET, &req);
	if (value == NULL && (p = alloca(name->len + 1)))
		nvram_user_get(slcpy(p, name->s, name->len), NULL);

	if (ret < 0 && (value || errno != ENOENT))
		perror(PATH_DEV_NVRAM);

	if (buf != tmp)
		free(buf);

	return ret;
}

static int _nvram_trim_set(const char *name, const char *value)
{
	str name_s, value_s;

	if (nvram_init() || strim(&name_s, name) == 0)
		return -1;

	if (value)
		strim(&value_s, value);

	return _nvram_set(&name_s, (value) ? &value_s : NULL);
}

int nvram_set(const char *name, const char *value)
{
	return _nvram_trim_set(name, value);
}

int nvram_unset(const char *name)
{
	return _nvram_trim_set(name, NULL);
}

__attribute__((weak)) int pthread_create(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *);
static inline int lock(pthread_mutex_t *mutex)
{
	return (pthread_create) ? pthread_mutex_lock(mutex) : 0;
}

static inline int unlock(pthread_mutex_t *mutex)
{
	return (pthread_create) ? pthread_mutex_unlock(mutex) : 0;
}

static int strcmp_and_free(const char *s1, const char *s2)
{
	int n = strcmp(s1, s2);
	return n ? : ({ free((void *)s2); 0; });
}

static char *nvram_user_get(const char *name, char *value)
{
	static pthread_mutex_t tree_safe = PTHREAD_MUTEX_INITIALIZER;
	static void *rootv = NULL;
	char *p = NULL;
	void *vp;

	if (!value) {
		tdelete(name, &rootv, (void *)strcmp_and_free);
		return NULL;
	}

	if (asprintf(&p, "%s%c%s%c", name, '\0', value ? : "", '\0') < 0)
		return NULL;

	lock(&tree_safe);

	vp = tsearch(p, &rootv, (void *)strcmp);
	if (vp && (*(char **)vp != p)) {
		free(*(char **)vp);
		*(char **)vp = p;
	}

	unlock(&tree_safe);
	return p + strnlen(p, SHRT_MAX) + 1;
}

int nvram_commit(void)
{
	char *buf;
	int ret = -1;

	buf = malloc(NVRAM_SPACE);
	if (buf) {
		ret = _nvram_getall(buf, NVRAM_SPACE - NVRAM_HEADER_SIZE, 1);
		free(buf);
	}
	return ret;
}

char *_nvram_get_r(char *name, char *buf, int bufsize, char *dfl)
{
	if (buf != NULL && bufsize > 0) {
		char *value = nvram_get(name) ? : dfl;
		if (value) {
			buf[--bufsize] = '\0';
			return strncpy(buf, value, bufsize);
		}
	}
	return NULL;
}

#define in_range(c, lo, up)  ((int)c >= lo && (int)c <= up)
#define isdigit(c) in_range(c, '0', '9')
#define isxdigit(c) (isdigit(c) || in_range(c, 'a', 'f') || in_range(c, 'A', 'F'))
#define islower(c) in_range(c, 'a', 'z')

static char *b2h_xfrm(char *dst, const char *cp, int count)
{
	const char xdigits_upcase[] __attribute__((aligned(1))) = "0123456789ABCDEF";
	char *p = dst;

	while (count-- > 0) {
		unsigned char c = *cp++ & 0xff;
		*p++ = xdigits_upcase[c >> 4];
		*p++ = xdigits_upcase[c & 0xf];
	}
	*p = '\0';
	return dst;
}

static int h2b_xfrm(char *dst, const char *src, unsigned int len)
{
	unsigned int i, ii;
	unsigned char c;
	int val;

	for (i = 0; i < len; i += 2) {
		for (val = ii = 0; ii < 2; ii++) {
			c = *src++ & 0xff;
			if (isdigit(c))
				val = (val << 4) + (int)(c - '0');
			else if (isxdigit(c))
				val = (val << 4) | (int)(c + 10 - (islower(c) ? 'a' : 'A'));
			else
				return -1;
		}
		*dst++ = val;
	}

	return (*src) ? -1 : 0;
}

#define SHA256_DGST_LENGTH 32
#define SHA512_DGST_LENGTH 64

static int nvram_sha2_set(const char *name, const char *value, size_t dgst_len)
{
	str name_s, value_s;
	uint8_t md[dgst_len];

	if (nvram_init() || !strim(&name_s, name))
		return -1;
	else if (value == NULL)
		return _nvram_set(&name_s, NULL);
	else if (strim(&value_s, value) > 0) {
		switch (dgst_len) {
		case SHA256_DGST_LENGTH:
			if (kcapi_md_sha256((uint8_t *)value_s.s, value_s.len, md, dgst_len) != dgst_len)
				return -1;
			break;

		case SHA512_DGST_LENGTH:
			if (kcapi_md_sha512((uint8_t *)value_s.s, value_s.len, md, dgst_len) != dgst_len)
				return -1;
			break;

		default:
			return -1;
		}

		value_s.s = b2h_xfrm(alloca((dgst_len << 1) + 1), (char *)md, dgst_len);
		value_s.len = dgst_len << 1;
	}

	return _nvram_set(&name_s, &value_s);
}

int nvram_sha_256_set(const char *name, const char *value)
{
	return nvram_sha2_set(name, value, SHA256_DGST_LENGTH);
}

int nvram_sha_512_set(const char *name, const char *value)
{
	return nvram_sha2_set(name, value, SHA512_DGST_LENGTH);
}

static int nvram_sha2_cmp(const char *name, const char *plain, size_t dgst_len)
{
	uint8_t md[dgst_len], md2[dgst_len];
	unsigned int n;
	char *p;

	if (!plain || (n = strlen(plain)) == 0)
		return -1;

	p = nvram_get(name);
	if (!p || ((strlen(p) >> 1) != dgst_len))
		return -1;

	if (h2b_xfrm((char *)md, p, dgst_len << 1))
		return -1;

	switch (dgst_len) {
	case SHA256_DGST_LENGTH:
		if (kcapi_md_sha256((uint8_t *)plain, n, md2, dgst_len) != dgst_len)
			return -1;
		break;
	case SHA512_DGST_LENGTH:
		if (kcapi_md_sha512((uint8_t *)plain, n, md2, dgst_len) != dgst_len)
			return -1;
		break;
	default:
		return -1;
	}

	return memcmp(md, md2, dgst_len);
}

int nvram_sha_256_cmp(const char *name, const char *plain)
{
	return nvram_sha2_cmp(name, plain, SHA256_DGST_LENGTH);
}

int nvram_sha_512_cmp(const char *name, const char *plain)
{
	return nvram_sha2_cmp(name, plain, SHA512_DGST_LENGTH);
}

int nvram_aes_cbc_set(const char *name, const char *value)
{
	str name_s, value_s;

	if (nvram_init() || !strim(&name_s, name))
		return -1;
	else if (value == NULL)
		return _nvram_set(&name_s, NULL);
	else if (strim(&value_s, value) > 0) {
		char *p = nvram_aes_cbc_enc(value_s.s, (unsigned int *)&value_s.len);
		if (p == NULL)
			return -1;
		value_s.s = b2h_xfrm(alloca((value_s.len << 1) + 1),
		                     p, value_s.len);
		value_s.len <<= 1;
		free(p);
	}

	return _nvram_set(&name_s, &value_s);
}

int nvram_aes_cbc_get(const char *name, char *buf, unsigned int size)
{
	unsigned int len;
	char *p, *b, *value;

	if (!buf || size < 1)
		return -1;

	p = nvram_get(name);
	if (p == NULL)
		return -1;

	len = (unsigned int)strlen(p);
	b = alloca(len);
	if (h2b_xfrm(b, p, len))
		return -1;
	len >>= 1;
	value = nvram_aes_cbc_dec(b, &len);
	if (value) {
		*(char *)mempcpy(buf, value, (size > len) ? len : (size - 1)) = '\0';
		free(value);
		return 0;
	}
	return -1;
}
