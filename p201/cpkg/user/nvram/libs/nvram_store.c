#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <time.h>
#include <arpa/inet.h>
#if STORE_BIN2MTD
#include <mtd/mtd-user.h>
#endif

#include "nvram_private.h"
#include <bcmnvram.h>
#include "crypto_linux.h"
#include "minilzo.h"
#if !FIXED_KEY
#include "ktkst.h"
#endif

#define ROUNDUP(x, y) \
({							\
	const typeof(y) __y = y;			\
	(((x) + (__y - 1)) / __y) * __y;		\
})

#define ROUNDDOWN(x, y) \
({							\
	typeof(x) __x = (x);				\
	__x - (__x % (y));				\
})

#if STORE_BIN2MTD
static int mtd_open(const char *name, int flags);
#endif

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

static uint8_t nvram_calc_crc(struct nvram_header *h, void *buf, ssize_t count)
{
	struct nvram_header tmp;
	uint8_t crc;

	/* Little-endian CRC8 over the last 11 bytes of the header */
	tmp.crc_ver_init = htonl((h->crc_ver_init & NVRAM_CRC_VER_MASK));
	tmp.kern_start = htonl(h->kern_start);
	tmp.rootfs_start = htonl(h->rootfs_start);

	crc = crc8((uint8_t *)&tmp + NVRAM_CRC_START_POSITION,
		sizeof(struct nvram_header) - NVRAM_CRC_START_POSITION,
		CRC8_INIT_VALUE);

	/* Continue CRC8 over data bytes */
	return crc8((uint8_t *)buf, count, crc);
}

static void nvram_build_header(struct nvram_header *h, void *buf, ssize_t count)
{
	char *q, *p = nvram_get("x_sys_bootm");

	memset(h, 0, sizeof(*h));
	if (p != NULL) {
		uint32_t kernel = strtoul(p, &q, 16);
		if (*q) {
			uint32_t rootfs = strtoul(++q, NULL, 16);
			if (kernel < rootfs) {
				h->kern_start = kernel;
				h->rootfs_start = rootfs;
			}
		}
	}
	h->magic = NVRAM_MAGIC;
	h->crc_ver_init = (NVRAM_VERSION << 8);
	h->len = count + sizeof(*h);
	h->crc_ver_init |= nvram_calc_crc(h, buf, count);
}

static unsigned char _IV[16] = {	/* ri3os0xsy9t8hg@! */
	0x35, 0x76, 0x3d, 0xb5, 0x15, 0x5d, 0x74, 0x15,
	0x54, 0x7c, 0xf4, 0x5c, 0x56, 0xb6, 0x5b, 0x7f
};

static unsigned char dflk[16] = {	/* 7h*s@ejow91H$h2Y */
	0xa5, 0x13, 0x1c, 0xd8, 0x79, 0x17, 0x36, 0xd4,
	0xdb, 0xd4, 0x7b, 0x3a, 0x52, 0x67, 0xaf, 0xdd
};

static unsigned char *nvram_file_dist_key(bool kgen)
{
#if FIXED_KEY
	return dflk;
#else
	static unsigned char buf[2][16];
	if (kgen == true)
		ktkst_key_new(buf[0], buf[1], (uint8_t *)dflk);
	else
		ktkst_key_get(buf[0], buf[1], (uint8_t *)dflk);
	return (unsigned char *)buf;
#endif
}

#if STORE_BIN2MTD
static uint8_t *nvram_mem_open(const char *name, int *size, struct nvram_header *hdr)
{
	struct mtd_info_user mtd;
	int fd, len;
	void *buf = NULL;
	size_t realsize;

	fd = mtd_open(name, O_RDONLY);
	if (fd == -1)
		return NULL;

	ioctl(fd, MEMGETINFO, &mtd);
	if (mtd.size < MAX_NVRAM_SPACE)
		goto out;

	lseek(fd, mtd.size - MAX_NVRAM_SPACE, SEEK_SET);
	len = TEMP_FAILURE_RETRY(read(fd, hdr, sizeof(*hdr)));
	if (len != sizeof(*hdr))
		goto out;
	if (hdr->len < sizeof(*hdr) || hdr->len > MAX_NVRAM_SPACE)
		goto out;

	realsize = (hdr->len - sizeof(*hdr) + 15) & ~15;
	if (posix_memalign(&buf, sysconf(_SC_PAGESIZE), realsize))
		goto out;

	len = TEMP_FAILURE_RETRY(read(fd, buf, realsize));

	close(fd);

	if (len != (hdr->len - sizeof(*hdr)))
		goto out2;

	if (hdr->magic != NVRAM_MAGIC ||
	    nvram_calc_crc(hdr, buf, len) != (uint8_t)hdr->crc_ver_init)
		goto out2;

	if (size)
		*size = realsize;

	return (uint8_t *)buf;
out:
	close(fd);
out2:
	free(buf);
	return NULL;
}
#else
static uint8_t *nvram_mem_open(const char *path, int *size, struct nvram_header *hdr)
{
	struct iovec iov[2];
	struct stat sb;
	int fd, len;
	size_t realsize;
	void *buf;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return NULL;

	if (fstat(fd, &sb) || ((sb.st_mode & S_IFMT) != S_IFREG) || ((size_t)sb.st_size < sizeof(*hdr)))
		goto nil;

	realsize = ((size_t)sb.st_size - sizeof(*hdr) + 15) & ~15;
	if (posix_memalign(&buf, sysconf(_SC_PAGESIZE), realsize))
		goto nil;

	iov[0].iov_base = hdr;
	iov[0].iov_len = sizeof(*hdr);
	iov[1].iov_base = buf;
	iov[1].iov_len = realsize;
	len = TEMP_FAILURE_RETRY(readv(fd, iov, 2));

	if (len != (size_t)sb.st_size)
		goto nil;

	if (hdr->magic != NVRAM_MAGIC ||
	    nvram_calc_crc(hdr, buf, len - sizeof(*hdr)) != (uint8_t)hdr->crc_ver_init)
		goto nil;

	if (size)
		*size = realsize;
out:
	close(fd);
	return (uint8_t *)buf;
nil:
	free(buf);
	buf = NULL;
	goto out;
}
#endif

static uint8_t *nvram_decrypt(const char *path, lzo_uint *len, uint8_t *key, struct nvram_header *hdr)
{
	uint8_t *p, iv[16];
	int inlen = 0;

	p = nvram_mem_open(path, &inlen, hdr);
	if (p == NULL)
		return NULL;
	memcpy(iv, _IV, sizeof(iv));
	if (kcapi_cipher_dec_aes_cbc(key, 16, p, inlen, iv, p, inlen) != inlen)
		return ({ free(p); NULL; });
	if (len)
		*len = inlen - p[inlen - 1];
	return p;
}

int nvram_load(const char *path, void *dst)
{
#if !STORE_BIN2MTD
	struct stat sb;
#endif
	struct nvram_signature *sig;
	void *inflate_p;
	lzo_uint uninitialized_var(in_len);
	lzo_uint out_len;
	lzo_uint new_len;
	int r, i = 0;
	uint8_t *key;
#if FIXED_KEY
	const int keynr = 1;
#else
	const int keynr = 2;
#endif

#if !STORE_BIN2MTD
	if (stat(path, &sb) || ((sb.st_mode & S_IFMT) != S_IFREG))
		return NVRAM_ERR_NOFILE;
#endif
	for (key = nvram_file_dist_key(false); i < keynr; i++, key += 16) {
		sig = (struct nvram_signature *)nvram_decrypt(path, &in_len,
						key, (struct nvram_header *)dst);
		if (sig == NULL)
			return NVRAM_ERR_DECRYPT;

		if ((in_len < sizeof(*sig)) || (sig->magic != NVRAM_FILE_MAGIC) ||
		    crc8((unsigned char *)sig, in_len, 0))
			free(sig);
		else
			break;
	}
	if (i >= keynr)
		return NVRAM_ERR_DECRYPT;

	/* restore with an original lzo pad byte */
	*((lzo_bytep)sig + in_len - 1) = '\0';

	out_len = SWAP_BE32(sig->inflate_size);

	inflate_p = malloc(out_len);
	if (!inflate_p && ({ free(sig); 1; }))
		return NVRAM_ERR_SYS;

	new_len = out_len;

	r = lzo1x_decompress((lzo_bytep)(sig + 1), in_len - sizeof(*sig),
			inflate_p, &new_len, NULL);

	free(sig);

	if (r == LZO_E_OK) {
#if (LZO_E_OK != 0)
		r = 0;
#endif
		if (out_len == new_len) {
			if (out_len > (NVRAM_SPACE - nv_magic_sz))
				r = NVRAM_ERR_TOOBIG;
			else
				memcpy((char *)dst + sizeof(struct nvram_header), inflate_p, out_len);
		} else
			r = NVRAM_ERR_LENGTH;
	} else
		r = NVRAM_ERR_INFLATE;

	free(inflate_p);

	return r;
}

static int nvram_mem_pad_len(char *p, int len)
{
	char *q;
	int i, remaining = len & (16 - 1);

	q = p + (len & ~(16 - 1));
	for (i = remaining, q += remaining; i < 16; i++)
		*q++ = (16 - remaining);
	return (int)(q - p);
}

static void *nvram_mem_deflate(void *src, size_t size, int *len)
{
	struct nvram_signature *sig;
	lzo_uint out_len;
	int r;
	lzo_align_t *wrkmem;

	out_len = (size + 4 + 16) << 1;

	if (posix_memalign((void **)&sig, sysconf(_SC_PAGESIZE), out_len + sizeof(*sig)))
		return NULL;

	wrkmem = (lzo_align_t *)calloc(ROUNDUP(LZO1X_1_MEM_COMPRESS, sizeof(lzo_align_t)), 1);
	if (!wrkmem && ({ free(sig); 1; }))
		return NULL;

	r = lzo1x_1_compress(src, size, (lzo_bytep)(sig + 1), &out_len, wrkmem);
	free(wrkmem);
	if (r != LZO_E_OK && ({ free(sig); 1; }))
		return NULL;

	sig->magic = NVRAM_FILE_MAGIC;
	sig->inflate_size = SWAP_BE32(size);

	*len = nvram_mem_pad_len((char *)sig, sizeof(*sig) + out_len);

	*((lzo_bytep)(sig + 1) + out_len - 1) = crc8((lzo_bytep)sig, sizeof(*sig) + out_len - 1, 0);

	return sig;
}

#if STORE_BIN2MTD
static int mtd_open(const char *name, int flags)
{
	char *p, buf[80];
	int i, fd = -1;
	FILE *f = fopen("/proc/mtd", "r");

	if (f == NULL)
		return -1;
	p = alloca(strlen(name) + 3);
	sprintf(p, "\"%s\"", name);
	while (fgets(buf, sizeof(buf), f)) {
		if (!strstr(buf, p) || sscanf(buf, "mtd%d:", &i) != 1)
			continue;
		snprintf(buf, sizeof(buf), "/dev/mtd%d", i);
		fd = open(buf, flags);
		break;
	}
	fclose(f);
	return fd;
}

static int mtd_erase(int fd, uint32_t off, size_t len, uint32_t erasesize)
{
	erase_info_t erase = { .length = erasesize, };

	len = ROUNDUP(off + len, erasesize);
	for (off = ROUNDDOWN(off, erasesize); off < len; off += erasesize) {
		erase.start = off;
		ioctl(fd, MEMUNLOCK, &erase);
		if (ioctl(fd, MEMERASE, &erase))
			return -1;
	}
	return 0;
}

static int nvram_mtd_store(const char *name, struct nvram_header *h, void *buf, ssize_t count)
{
	struct iovec iov[2];
	struct mtd_info_user mtd;
	u_int32_t magic = h->magic;
	int fd, sts = -1;

	fd = mtd_open(name, O_RDWR);
	if (fd == -1)
		return -1;

	ioctl(fd, MEMGETINFO, &mtd);
	if (mtd.size < MAX_NVRAM_SPACE)
		goto out;

	if (mtd_erase(fd, mtd.size - MAX_NVRAM_SPACE, h->len, mtd.erasesize))
		goto out;

	h->magic = NVRAM_INVALID_MAGIC;
	lseek(fd, mtd.size - MAX_NVRAM_SPACE, SEEK_SET);

	iov[0].iov_base = h;
	iov[0].iov_len = sizeof(*h);
	iov[1].iov_base = buf;
	iov[1].iov_len = count;

	if (TEMP_FAILURE_RETRY(writev(fd, iov, 2)) != (sizeof(*h) + count))
		goto out;

	lseek(fd, mtd.size - MAX_NVRAM_SPACE, SEEK_SET);
	if (TEMP_FAILURE_RETRY(write(fd, &magic, sizeof(h->magic))) != sizeof(h->magic))
		goto out;

	sts = 0;
out:
	close(fd);
	return sts;
}
#else
static int nvram_file_store(struct nvram_header *h, void *buf, size_t count)
{
	struct iovec iov[2];
	char *tmp = NULL;
	int fd, n, r = -1;

	asprintf(&tmp, "%sXXXXXX", NVRAM_FILE_NAME);
	fd = mkstemp(tmp);
	if (fd > -1) {
		iov[0].iov_base = h;
		iov[0].iov_len = sizeof(*h);
		iov[1].iov_base = buf;
		iov[1].iov_len = count;

		n = TEMP_FAILURE_RETRY(writev(fd, iov, 2));
		if ((n != (sizeof(*h) + count)) || (r = rename(tmp, NVRAM_FILE_NAME)))
			unlink(tmp);
		else
			fsync(fd);
		close(fd);
#ifdef NVRAM_BAK_NAME
		if (!r && ((fd = open(NVRAM_BAK_NAME, O_CREAT|O_RDWR, 0600)) > -1)) {
			h->magic = NVRAM_MAGIC2;
			n = TEMP_FAILURE_RETRY(writev(fd, iov, 2));
			if (n == (sizeof(*h) + count)) {
				ftruncate(fd, (sizeof(*h) + count));
				fsync(fd);
			}
			close(fd);
		}
#endif
	}
	free(tmp);
	return r;
}
#endif

__hidden int nvram_store(void *src, size_t size)
{
	struct nvram_header hdr;
	struct nvram_signature *sig;
	uint8_t iv[16], key[16];
	int fsz = 0, r = -1;

	sig = nvram_mem_deflate(src, size, &fsz);
	if (!sig)
		return NVRAM_ERR_DEFLATE;

	memcpy(iv, _IV, sizeof(iv));
	memcpy(key, nvram_file_dist_key(true), sizeof(key));
	kcapi_cipher_enc_aes_cbc(key, sizeof(key), (uint8_t *)sig, fsz, iv, (uint8_t *)sig, fsz);

	nvram_build_header(&hdr, (void *)sig, fsz);
#if STORE_BIN2MTD
	r = nvram_mtd_store("nvram", &hdr, sig, fsz);
	if (r == 0 && ({ hdr.magic = NVRAM_MAGIC2; 1; }))
		nvram_mtd_store("b_nvram", &hdr, sig, fsz);
#else
	r = nvram_file_store(&hdr, sig, fsz);
#endif
	free(sig);
	return r;
}

__hidden char *nvram_aes_cbc_enc(const char *in, unsigned int *len)
{
	uint8_t *out;
	uint32_t outlen;
	uint8_t iv[16], key[16];

	if (!len || !*len)
		return NULL;

	outlen = (*len + 16) & ~15;
	if (posix_memalign((void **)&out, sysconf(_SC_PAGESIZE), outlen))
		return NULL;

	memcpy(iv, _IV, sizeof(iv));
	memcpy(key, dflk, sizeof(key));
	memcpy(out, in, *len);
	nvram_mem_pad_len((char *)out, (int)*len);

	if (kcapi_cipher_enc_aes_cbc(key, sizeof(key),
	                             out, outlen, iv, out, outlen) != outlen) {
		free(out);
		out = NULL;
	} else
		*len = outlen;
	return (char *)out;
}

__hidden char *nvram_aes_cbc_dec(const char *in, unsigned int *len)
{
	uint8_t iv[16], key[16];
	uint8_t *out;
	uint32_t outlen;

	if (!len || !*len || (*len & 15))
		return NULL;

	outlen = *len;
	if (posix_memalign((void **)&out, sysconf(_SC_PAGESIZE), outlen))
		return NULL;

	memcpy(iv, _IV, sizeof(iv));
	memcpy(key, dflk, sizeof(key));
	memcpy(out, in, *len);

	if ((kcapi_cipher_dec_aes_cbc(key, sizeof(key), out, outlen,
	                              iv, out, outlen) != outlen)
	    && (out[outlen - 1] >= 16)) {
		free(out);
		out = NULL;
	} else
		*len = outlen - out[outlen - 1];
	return (char *)out;
}

static void __attribute__ ((constructor)) nvram_file_ctor(void)
{
	unsigned char c;
	int m;

	for (m = 0; m < sizeof(dflk); ++m) {
		c = dflk[m];
		c += m;
		c = (c >> 0x3) | (c << 0x5);
		c ^= m;
		c += 0x14;
		c = ~c;
		dflk[m] = c;
	}

	for (m = 0; m < sizeof(_IV); ++m) {
		c = _IV[m];
		c = (c >> 0x6) | (c << 0x2);
		c = ~c;
		c -= 0x2a;
		c = (c >> 0x7) | (c << 0x1);
		c += 0x70;
		_IV[m] = c;
	}
}
