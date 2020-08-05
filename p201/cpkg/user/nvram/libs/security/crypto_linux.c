#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <limits.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/uio.h>

#include <linux/if_alg.h>
#include "crypto_linux.h"

#ifndef ALG_MAX_PAGES
#define ALG_MAX_PAGES 16
#endif

#ifndef SOL_ALG
#define SOL_ALG 279
#endif

/* Boolean variable */
enum { false, true };
typedef _Bool bool;

enum kcapi_verbosity {
	KCAPI_LOG_NONE,
	KCAPI_LOG_ERR,
	KCAPI_LOG_WARN,
	KCAPI_LOG_VERBOSE,
	KCAPI_LOG_DEBUG,
};

#ifndef _NDEBUG
#define kcapi_dolog(p, arg...) \
	do {\
		fprintf(stderr, arg); putc('\n', stderr); \
	} while (0)
#else
#define kcapi_dolog(p, arg...) do {} while (0)
#endif

enum kcapi_cipher_type {
	KCAPI_CIPHER_SKCIPHER,
	KCAPI_CIPHER_AEAD,
	KCAPI_CIPHER_KDF,
	KCAPI_CIPHER_RNG,
	KCAPI_CIPHER_MD,
	KCAPI_CIPHER_KPP,
	KCAPI_CIPHER_AKCIPHER,
};

/**
 * Information obtained for different ciphers during handle init time
 * using the NETLINK_CRYPTO interface.
 * @blocksize block size of cipher (hash, symmetric, AEAD)
 * @ivsize size of IV of cipher (symmetric, AEAD)
 * @hash_digestsize size of message digest (hash)
 * @blk_min_keysize minimum key size (symmetric)
 * @blk_max_keysize maximum key size (symmetric)
 * @aead_maxauthsize maximum authentication tag size (AEAD)
 * @rng_seedsize seed size (RNG)
 */
struct kcapi_cipher_info {
	enum kcapi_cipher_type cipher_type;
	/* generic */
	uint32_t blocksize;
	uint32_t ivsize;
	/* hash */
	uint32_t hash_digestsize;
	/* blkcipher */
	uint32_t blk_min_keysize;
	uint32_t blk_max_keysize;
};

struct kcapi_flags {
	/*
	 * A flag to distinguish the new AEAD interface introduced with 4.9.0 to
	 * only require a tag if it is required as input or output.
	 *
	 * Also, kernels before 4.9.0 misbehave when no data is sent for hashing.
	 */
	bool ge_v4_9;

	/* AF_ALG interfaces changed to process more pages concurrently. */
	uint32_t alg_max_pages;
};

struct kcapi_handle_tfm {
	int tfmfd;
	struct kcapi_cipher_info info;
};

struct kcapi_cipher_data {
	uint8_t *iv;
};

struct kcapi_handle {
	struct kcapi_handle_tfm *tfm;
	int pipes[2];
	int opfd;
	uint32_t processed_sg;
	struct kcapi_cipher_data cipher;
	struct kcapi_flags flags;
};

#define kcapi_memset_secure memset

static inline int *_kcapi_get_opfd(struct kcapi_handle *handle)
{
	return &handle->opfd;
}

static int _kcapi_common_accept(struct kcapi_handle *handle)
{
	struct kcapi_handle_tfm *tfm = handle->tfm;
	int fd;

	if (*_kcapi_get_opfd(handle) != -1)
		return 0;

	fd = accept(tfm->tfmfd, NULL, 0);
	if (fd == -1) {
		int errsv;

		errsv = errno;
		kcapi_dolog(KCAPI_LOG_ERR, "AF_ALG: accept failed");
		return -errsv;
	}
	kcapi_dolog(KCAPI_LOG_DEBUG, "AF_ALG: accept syscall successful");

	*_kcapi_get_opfd(handle) = fd;

	return 0;
}

static int _kcapi_handle_alloc(struct kcapi_handle **caller)
{
	struct kcapi_handle *handle = calloc(1, sizeof(struct kcapi_handle));

	if (!handle)
		return -ENOMEM;

	*_kcapi_get_opfd(handle) = -1;
	handle->pipes[0] = -1;
	handle->pipes[1] = -1;

	*caller = handle;

	return 0;
}

static void _kcapi_handle_destroy_tfm(struct kcapi_handle *handle)
{
	struct kcapi_handle_tfm *tfm;
	if (!handle || !handle->tfm)
		return;

	tfm = handle->tfm;
	if (tfm->tfmfd != -1)
		close(tfm->tfmfd);
	kcapi_memset_secure(tfm, 0, sizeof(*tfm));
	free(tfm);
	handle->tfm = NULL;
}

static void _kcapi_handle_destroy(struct kcapi_handle *handle)
{
	if (!handle)
		return;
	if (*_kcapi_get_opfd(handle) != -1)
		close(*_kcapi_get_opfd(handle));
	if (handle->pipes[0] != -1)
		close(handle->pipes[0]);
	if (handle->pipes[1] != -1)
		close(handle->pipes[1]);
	_kcapi_handle_destroy_tfm(handle);
	kcapi_memset_secure(handle, 0, sizeof(struct kcapi_handle));
	free(handle);
}

static void _kcapi_handle_flags(struct kcapi_handle *handle)
{
	handle->flags.ge_v4_9 = false;
	handle->flags.alg_max_pages = ALG_MAX_PAGES;
}

static int _kcapi_handle_init_op(struct kcapi_handle *handle, uint32_t flags)
{
	int ret;

	ret = pipe(handle->pipes);
	if (ret) {
		ret = -errno;
		kcapi_dolog(KCAPI_LOG_ERR, "AF_ALG: pipe syscall failed (errno: %d)", ret);
		return ret;
	}
	kcapi_dolog(KCAPI_LOG_DEBUG, "AF_ALG: pipe syscall passed");
	_kcapi_handle_flags(handle);

	return ret;
}

static int _kcapi_handle_init_tfm(struct kcapi_handle *handle, const char *type, const char *ciphername)
{
	struct kcapi_handle_tfm *tfm = handle->tfm;
	struct sockaddr_alg sa;
	int ret;

	tfm->tfmfd = -1;
	memset(&sa, 0, sizeof(sa));
	sa.salg_family = AF_ALG;
	snprintf((char *)sa.salg_type, sizeof(sa.salg_type), "%s", type);
	snprintf((char *)sa.salg_name, sizeof(sa.salg_name), "%s", ciphername);

	tfm->tfmfd = socket(AF_ALG, SOCK_SEQPACKET, 0);
	if (tfm->tfmfd == -1) {
		ret = -errno;
		kcapi_dolog(KCAPI_LOG_ERR, "AF_ALG: socket syscall failed (errno: %d)", ret);
		return ret;
	}
	kcapi_dolog(KCAPI_LOG_DEBUG, "AF_ALG: socket syscall passed");

	if (bind(tfm->tfmfd, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
		ret = -errno;
		kcapi_dolog(KCAPI_LOG_ERR, "AF_ALG: bind failed (errno: %d)", ret);
		return ret;
	}
	kcapi_dolog(KCAPI_LOG_DEBUG, "AF_ALG: bind syscall passed");

	if (!strcmp(ciphername, "cbc(aes)")) {
		tfm->info.cipher_type = KCAPI_CIPHER_SKCIPHER;
		tfm->info.blocksize = 16;
		tfm->info.ivsize = 16;
		tfm->info.blk_min_keysize = 16;
		tfm->info.blk_max_keysize = 32;
	} else if (!strncmp(ciphername, "sha", 3)) {
		tfm->info.cipher_type = KCAPI_CIPHER_MD;
		tfm->info.hash_digestsize = (strtol(ciphername + 3, NULL, 10) >> 3) ? : 20;
		tfm->info.blocksize = 64;
	} else
		return -1;
	return 0;
}

static int32_t _kcapi_common_send_data(struct kcapi_handle *handle, struct iovec *iov, uint32_t iovlen, uint32_t flags)
{
	struct msghdr msg;
	int32_t ret;

	ret = _kcapi_common_accept(handle);
	if (ret)
		return ret;

	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags = 0;
	msg.msg_iov = iov;
	msg.msg_iovlen = iovlen;

	ret = sendmsg(*_kcapi_get_opfd(handle), &msg, flags);
	if (ret < 0)
		ret = -errno;
	kcapi_dolog(KCAPI_LOG_DEBUG, "AF_ALG: sendmsg syscall returned %d", ret);

	return ret;
}

static int32_t _kcapi_common_send_meta(struct kcapi_handle *handle,
				       struct iovec *iov, uint32_t iovlen, uint32_t enc, uint32_t flags)
{
	struct kcapi_handle_tfm *tfm = handle->tfm;
	int32_t ret;
	char buffer_static[80] = { 0 };
	char *buffer_p = buffer_static;
	char *buffer_alloc = NULL;

	/* plaintext / ciphertext data */
	struct cmsghdr *header = NULL;
	uint32_t *type = NULL;
	struct msghdr msg;

	/* IV data */
	struct af_alg_iv *alg_iv = NULL;
	uint32_t iv_msg_size = handle->cipher.iv ? CMSG_SPACE(sizeof(*alg_iv) + tfm->info.ivsize) : 0;

	uint32_t bufferlen = CMSG_SPACE(sizeof(*type)) +	/* Encryption / Decryption */
	    iv_msg_size;	/* IV */

	ret = _kcapi_common_accept(handle);
	if (ret)
		return ret;

	memset(&msg, 0, sizeof(msg));

	/* allocate buffer, if static buffer is too small */
	if (bufferlen > sizeof(buffer_static)) {
		buffer_alloc = calloc(1, bufferlen);
		if (!buffer_alloc)
			return -ENOMEM;
		buffer_p = buffer_alloc;
		kcapi_dolog(KCAPI_LOG_VERBOSE, "_kcapi_common_send_meta_fd: "
			"submission buffer of size %u allocated", bufferlen);
	}

	msg.msg_control = buffer_p;
	msg.msg_controllen = bufferlen;
	msg.msg_iov = iov;
	msg.msg_iovlen = iovlen;

	/* encrypt/decrypt operation */
	header = CMSG_FIRSTHDR(&msg);
	if (!header) {
		ret = -EFAULT;
		goto out;
	}
	header->cmsg_level = SOL_ALG;
	header->cmsg_type = ALG_SET_OP;
	header->cmsg_len = CMSG_LEN(sizeof(*type));
	type = (void *)CMSG_DATA(header);
	*type = enc;

	/* set IV */
	if (handle->cipher.iv) {
		header = CMSG_NXTHDR(&msg, header);
		if (!header) {
			ret = -EFAULT;
			goto out;
		}
		header->cmsg_level = SOL_ALG;
		header->cmsg_type = ALG_SET_IV;
		header->cmsg_len = iv_msg_size;
		alg_iv = (void *)CMSG_DATA(header);
		alg_iv->ivlen = tfm->info.ivsize;
		memcpy(alg_iv->iv, handle->cipher.iv, tfm->info.ivsize);
	}

	ret = sendmsg(*_kcapi_get_opfd(handle), &msg, flags);
	if (ret < 0)
		ret = -errno;
	kcapi_dolog(KCAPI_LOG_DEBUG, "AF_ALG: sendmsg syscall returned %d", ret);

 out:
	kcapi_memset_secure(buffer_p, 0, bufferlen);
	if (buffer_alloc)
		free(buffer_alloc);
	return ret;
}

static int32_t _kcapi_common_vmsplice_chunk(struct kcapi_handle *handle, const uint8_t *in, uint32_t inlen, uint32_t flags)
{
	struct iovec iov;
	uint32_t processed = 0;
	int32_t ret = 0;
	uint32_t sflags = (flags & SPLICE_F_MORE) ? MSG_MORE : 0;

	if (inlen > INT_MAX)
		return -EMSGSIZE;

	if (!inlen)
		return _kcapi_common_send_data(handle, NULL, 0, sflags);

	ret = _kcapi_common_accept(handle);
	if (ret)
		return ret;

	while (inlen) {
		iov.iov_base = (void *)(uintptr_t) (in + processed);
		iov.iov_len = inlen;

		if ((handle->processed_sg++) > handle->flags.alg_max_pages) {
			ret = _kcapi_common_send_data(handle, &iov, 1, sflags);
			if (ret < 0)
				return ret;
		} else {
			ret = vmsplice(handle->pipes[1], &iov, 1, SPLICE_F_GIFT | flags);
			if (ret < 0) {
				ret = -errno;
				kcapi_dolog(KCAPI_LOG_DEBUG, "AF_ALG: vmsplice syscall returned %d", ret);
				return ret;
			}
			kcapi_dolog(KCAPI_LOG_DEBUG, "AF_ALG: vmsplice syscall returned %d", ret);

			ret = splice(handle->pipes[0], NULL, *_kcapi_get_opfd(handle), NULL, ret, flags);
			if (ret < 0) {
				ret = -errno;
				kcapi_dolog(KCAPI_LOG_DEBUG, "AF_ALG: splice syscall returned %d", ret);
				return ret;
			}
			kcapi_dolog(KCAPI_LOG_DEBUG, "AF_ALG: splice syscall returned %d", ret);
		}

		processed += ret;
		inlen -= ret;
	}

	return processed;
}

static int32_t _kcapi_common_recv_data(struct kcapi_handle *handle, struct iovec *iov, uint32_t iovlen)
{
	struct msghdr msg;
	int32_t ret;

	ret = _kcapi_common_accept(handle);
	if (ret)
		return ret;

	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags = 0;
	msg.msg_iov = iov;
	msg.msg_iovlen = iovlen;

	ret = recvmsg(*_kcapi_get_opfd(handle), &msg, 0);
	if (ret < 0)
		ret = -errno;
	kcapi_dolog(KCAPI_LOG_DEBUG, "AF_ALG: recvmsg syscall returned %d", ret);

	/*
	 * As the iovecs are processed and removed from the list in the kernel
	 * we can also reset the list of processed iovecs here.
	 *
	 * Note, if there is an error, the kernel keeps the list unless it is
	 * a "valid" error of EBADMSG indicating an integrity error of the
	 * crypto operation.
	 */
	if (ret >= 0 || ret == -EBADMSG)
		handle->processed_sg = 0;

#if 0
	/*
	 * Truncated message digests can be identified with this check.
	 */
	if (msg.msg_flags & MSG_TRUNC) {
		fprintf(stderr, "recvmsg: processed data was truncated by kernel (only %lu bytes processed)\n",
			(unsigned long)ret);
		return -EMSGSIZE;
	}
#endif

	return ret;
}

static int32_t _kcapi_common_read_data(struct kcapi_handle *handle, uint8_t *out, uint32_t outlen)
{
	int ret;
	int32_t totallen = 0;

	if (outlen > INT_MAX)
		return -EMSGSIZE;

	ret = _kcapi_common_accept(handle);
	if (ret)
		return ret;

	if (outlen) {
		do {
			ret = read(*_kcapi_get_opfd(handle), out, outlen);
			if (ret > 0) {
				out += ret;
				outlen -= ret;
				totallen += ret;
			}
			kcapi_dolog(KCAPI_LOG_DEBUG, "AF_ALG: read syscall returned %d", ret);
		} while ((ret > 0 || errno == EINTR) && outlen);

		if (ret < 0)
			return -errno;
	}

	return totallen;
}

static int32_t _kcapi_cipher_crypt(struct kcapi_handle *handle, const uint8_t *in,
				   uint32_t inlen, uint8_t *out, uint32_t outlen, int access, int enc)
{
	int32_t ret = 0;

	if (outlen > INT_MAX)
		return -EMSGSIZE;

	ret = _kcapi_common_send_meta(handle, NULL, 0, enc, inlen ? MSG_MORE : 0);
	if (0 > ret)
		return ret;
	ret = _kcapi_common_vmsplice_chunk(handle, in, inlen, 0);
	if (0 > ret)
		return ret;

	return _kcapi_common_read_data(handle, out, outlen);
}

static int32_t _kcapi_cipher_crypt_chunk(struct kcapi_handle *handle,
					 const uint8_t *in, uint32_t inlen,
					 uint8_t *out, uint32_t outlen, int access, int enc)
{
	int32_t totallen = 0;
	uint32_t maxprocess = sysconf(_SC_PAGESIZE) * ALG_MAX_PAGES;
	int32_t ret;
	uint8_t iv[handle->tfm->info.ivsize ? : 16];

	if (outlen > INT_MAX)
		return -EMSGSIZE;

	while (inlen && outlen) {
		uint32_t inprocess = inlen;
		uint32_t outprocess = outlen;

		/*
		 * We do not check that sysconf(_SC_PAGESIZE) * ALG_MAX_PAGES is
		 * a multiple of blocksize, because we assume that this is
		 * always the case.
		 */
		if (inlen > maxprocess)
			inprocess = maxprocess;
		if (outlen > maxprocess)
			outprocess = maxprocess;

		if (inprocess == maxprocess && inlen > maxprocess && enc == ALG_OP_DECRYPT)
			memcpy(iv, &in[maxprocess - sizeof(iv)], sizeof(iv));

		ret = _kcapi_cipher_crypt(handle, in, inprocess, out, outprocess, access, enc);
		if (ret < 0)
			return ret;

		totallen += inprocess;
		in += inprocess;
		inlen -= inprocess;
		out += ret;
		outlen -= ret;

		if (inprocess == maxprocess && inlen > 0) {
			if (enc == ALG_OP_ENCRYPT)
				memcpy(handle->cipher.iv, out - sizeof(iv), sizeof(iv));
			else
				memcpy(handle->cipher.iv, iv, sizeof(iv));
		}
	}

	return totallen;
}

static int32_t kcapi_cipher_encrypt(struct kcapi_handle *handle,
				    const uint8_t *in, uint32_t inlen,
				    uint8_t *iv, uint8_t *out, uint32_t outlen, int access)
{
	struct kcapi_handle_tfm *tfm = handle->tfm;
	uint32_t bs = tfm->info.blocksize;

	/* require properly sized output data size */
	if (outlen < ((inlen + bs - 1) / bs * bs))
		kcapi_dolog(KCAPI_LOG_WARN,
			    "Symmetric Encryption: Ciphertext buffer (%lu) is not "
			    "plaintext buffer (%lu) rounded up to multiple of block size %u",
			    (unsigned long)outlen, (unsigned long)inlen, bs);

	handle->cipher.iv = iv;
	return _kcapi_cipher_crypt_chunk(handle, in, inlen, out, outlen, access, ALG_OP_ENCRYPT);
}

static int32_t kcapi_cipher_decrypt(struct kcapi_handle *handle,
				    const uint8_t *in, uint32_t inlen,
				    uint8_t *iv, uint8_t *out, uint32_t outlen, int access)
{
	struct kcapi_handle_tfm *tfm = handle->tfm;

	/* require properly sized output data size */
	if (inlen % tfm->info.blocksize)
		kcapi_dolog(KCAPI_LOG_WARN,
			    "Symmetric Decryption: Ciphertext buffer is not multiple of block size %u", tfm->info.blocksize);

	if (outlen < inlen)
		kcapi_dolog(KCAPI_LOG_WARN,
			    "Symmetric Decryption: Plaintext buffer (%lu) is smaller as ciphertext buffer (%lu)",
			    (unsigned long)outlen, (unsigned long)inlen);

	handle->cipher.iv = iv;
	return _kcapi_cipher_crypt_chunk(handle, in, inlen, out, outlen, access, ALG_OP_DECRYPT);
}

static int _kcapi_common_setkey(struct kcapi_handle *handle, const uint8_t *key, uint32_t keylen)
{
	struct kcapi_handle_tfm *tfm = handle->tfm;
	int ret;

	ret = setsockopt(tfm->tfmfd, SOL_ALG, ALG_SET_KEY, key, keylen);
	if (ret < 0)
		ret = -errno;
	kcapi_dolog(KCAPI_LOG_DEBUG, "AF_ALG setkey: setsockopt syscall returned %d", ret);

	return ret;
}

static int kcapi_cipher_setkey(struct kcapi_handle *handle, const uint8_t *key, uint32_t keylen)
{
	return _kcapi_common_setkey(handle, key, keylen);
}

static int _kcapi_handle_init(struct kcapi_handle **caller, const char *type, const char *ciphername, uint32_t flags)
{
	struct kcapi_handle *handle;
	struct kcapi_handle_tfm *tfm;
	int ret;

	ret = _kcapi_handle_alloc(&handle);
	if (ret)
		return ret;

	tfm = calloc(1, sizeof(struct kcapi_handle_tfm));
	if (!tfm) {
		free(handle);
		return -ENOMEM;
	}

	handle->tfm = tfm;

	ret = _kcapi_handle_init_tfm(handle, type, ciphername);
	if (ret)
		goto err;

	ret = _kcapi_handle_init_op(handle, flags);
	if (ret)
		goto err;

	*caller = handle;

	kcapi_dolog(KCAPI_LOG_VERBOSE, "communication for %s with kernel initialized", ciphername);

	return 0;

 err:
	_kcapi_handle_destroy(handle);
	return ret;
}

static int32_t kcapi_cipher_conv_enc_common(const char *name,
					    const uint8_t *key, uint32_t keylen,
					    const uint8_t *in, uint32_t inlen,
					    uint8_t *iv, uint8_t *out, uint32_t outlen, int enc)
{
	struct kcapi_handle *handle;
	int32_t ret = _kcapi_handle_init(&handle, "skcipher", name, 0);
	if (ret)
		return ret;

	ret = kcapi_cipher_setkey(handle, key, keylen);
	if (ret)
		goto out;

	ret = enc ? kcapi_cipher_encrypt(handle, in, inlen, iv, out, outlen, 0) :
	    kcapi_cipher_decrypt(handle, in, inlen, iv, out, outlen, 0);

 out:
	_kcapi_handle_destroy(handle);
	return ret;
}

__hidden int32_t kcapi_cipher_enc_aes_cbc(const uint8_t *key, uint32_t keylen,
					  const uint8_t *in, uint32_t inlen,
					  uint8_t *iv, uint8_t *out, uint32_t outlen)
{
	return kcapi_cipher_conv_enc_common("cbc(aes)", key, keylen, in, inlen, iv, out, outlen, true);
}

__hidden int32_t kcapi_cipher_dec_aes_cbc(const uint8_t *key, uint32_t keylen,
					  const uint8_t *in, uint32_t inlen,
					  uint8_t *iv, uint8_t *out, uint32_t outlen)
{
	return kcapi_cipher_conv_enc_common("cbc(aes)", key, keylen, in, inlen, iv, out, outlen, false);
}

static int32_t _kcapi_md_update(struct kcapi_handle *handle, const uint8_t *buffer, uint32_t len)
{
	int32_t ret = 0;

	if (len > INT_MAX)
		return -EMSGSIZE;

	/* zero buffer length cannot be handled via splice */
	if (len < (1 << 15)) {
		ret = _kcapi_common_accept(handle);
		if (ret)
			return ret;
		ret = send(*_kcapi_get_opfd(handle), buffer, len, MSG_MORE);
	} else {
		ret = _kcapi_common_vmsplice_chunk(handle, buffer, len, SPLICE_F_MORE);
	}

	if (ret < 0)
		return ret;
	if ((uint32_t) ret < len)
		return -EIO;

	handle->processed_sg += 1;
	return 0;
}

static int32_t _kcapi_md_final(struct kcapi_handle *handle, uint8_t *buffer, uint32_t len)
{
	struct iovec iov;
#ifndef _NDEBUG
	struct kcapi_handle_tfm *tfm = handle->tfm;
#endif
	if (!buffer || !len) {
		kcapi_dolog(KCAPI_LOG_ERR,
			    "Message digest: output buffer too small (seen %lu - required %u)",
			    (unsigned long)len, tfm->info.hash_digestsize);
		return -EINVAL;
	}

	/* Work around zero-sized hashing bug in pre-4.9 kernels: */
	if (!handle->flags.ge_v4_9 && !handle->processed_sg)
		_kcapi_md_update(handle, NULL, 0);

	iov.iov_base = (void *)(uintptr_t) buffer;
	iov.iov_len = len;
	return _kcapi_common_recv_data(handle, &iov, 1);
}

static int32_t kcapi_md_digest(struct kcapi_handle *handle, const uint8_t *in, uint32_t inlen, uint8_t *out, uint32_t outlen)
{
	int32_t ret = 0;

	ret = _kcapi_md_update(handle, in, inlen);
	if (0 > ret)
		return ret;
	return _kcapi_md_final(handle, out, outlen);
}

static inline int32_t kcapi_md_conv_common(const char *name, const uint8_t *in, uint32_t inlen, uint8_t *out, uint32_t outlen)
{
	struct kcapi_handle *handle;
	int32_t ret = _kcapi_handle_init(&handle, "hash", name, 0);

	if (ret)
		return ret;

	ret = kcapi_md_digest(handle, in, inlen, out, outlen);

	_kcapi_handle_destroy(handle);

	return ret;
}

__hidden int32_t kcapi_md_sha256(const uint8_t *in, uint32_t inlen, uint8_t *out, uint32_t outlen)
{
	return kcapi_md_conv_common("sha256", in, inlen, out, outlen);
}

__hidden int32_t kcapi_md_sha512(const uint8_t *in, uint32_t inlen, uint8_t *out, uint32_t outlen)
{
	return kcapi_md_conv_common("sha512", in, inlen, out, outlen);
}
