#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>

#include "crypto_linux.h"
#include "kst.h"
#include "ktkst.h"
#include "file_utils.h"

#define DATA_ENCRYPT_USED 1
#if 0 /* move to file_utils.h */
#define KTKST_BACKUP 1
#endif

/* !!!! ktkst assumes key length 16Bytes */

#define KTKST_KEY_LEN 16

#define KTKST_IDX_KEY1 0
#define KTKST_IDX_KEY2 1

//////////////////////////////////////////////////////////////////////
// TODO NEED CUSTOMIZING
//////////////////////////////////////////////////////////////////////
#define HASH_STR (unsigned char *)"abcdefgh"
#define HASH_STR_LEN 8

static unsigned char *enc_key_get(void)
{
	return (unsigned char *)"IamProgrammingNow!";
}

//////////////////////////////////////////////////////////////////////
// END OF NEED CUSTOMIZING
//////////////////////////////////////////////////////////////////////

static void _random_key(unsigned char *key, int len)
{
	kst_rand_str_get(key, len);
}

#if DATA_ENCRYPT_USED
//////////////////////////////////////////////////////////////////////
// encrypt/decrypt
//////////////////////////////////////////////////////////////////////

typedef unsigned char _uint8;
#define AES_KEY_LEN 16
#define AES_BLOCK_SZ 16
#define AES_IV     KST_MAGIC_MARK	//"abcdefghijklmnop"

static int sys_aes_cbc_dec_nopad(_uint8 *d, int dlen, _uint8 *e, int elen, _uint8 *key)
{
	_uint8 iv[AES_KEY_LEN];

	if (!key || !key[0])
		return -1;

	if (dlen < elen)
		return -2;

	if ((elen % AES_BLOCK_SZ) != 0)
		return -3;

	memcpy(iv, AES_IV, AES_KEY_LEN);
	return kcapi_cipher_dec_aes_cbc(key, AES_KEY_LEN, e, elen, iv, d, elen);
}

static int sys_aes_cbc_enc_nopad(_uint8 *e, int elen, _uint8 *d, int dlen, _uint8 *key)
{
	_uint8 iv[AES_KEY_LEN];

	if (!key || !key[0])
		return -1;

	if (dlen % AES_BLOCK_SZ)
		return -2;	// original data len must be aligned to AES_BLOCK_SZ

	if (elen < dlen)
		return -3;

	memcpy(iv, AES_IV, AES_KEY_LEN);
	return kcapi_cipher_enc_aes_cbc(key, AES_KEY_LEN, d, dlen, iv, e, dlen);
}

static int _dec_data(unsigned char *e, int e_sz, unsigned char *d, int *d_sz)
{
	int len;
	len = sys_aes_cbc_dec_nopad(d, *d_sz, e, e_sz, enc_key_get());
	if (len > 0)
		*d_sz = len;
	return len;
}

static int _enc_data(unsigned char *d, int d_sz, unsigned char *e, int *e_sz)
{
	int len;
	len = sys_aes_cbc_enc_nopad(e, *e_sz, d, d_sz, enc_key_get());
	if (len > 0)
		*e_sz = len;
	return len;
}

//////////////////////////////////////////////////////////////////////
// encrypt/decrypt end
//////////////////////////////////////////////////////////////////////
#endif

static int _ktkst_get(struct kst_t *kst, int idx, unsigned char *data, int data_sz)
{
#if DATA_ENCRYPT_USED
	int ret;
	unsigned char out[KTKST_KEY_LEN * 2];
	int out_sz = sizeof(out);

	ret = kst_get(kst, idx, out, out_sz);
	if (ret < 0)
		return ret;

	if (_dec_data(out, ret, data, &data_sz) < 0)
		return -98;

	return data_sz;
#else
	return kst_get(kst, idx, data, data_sz);
#endif
}

static int _ktkst_update(struct kst_t *kst, int idx, unsigned char *data, int data_sz)
{
#if DATA_ENCRYPT_USED
	int ret;
	unsigned char out[data_sz * 2];
	int out_sz = sizeof(out);

	if (_enc_data(data, data_sz, out, &out_sz) < 0)
		return -99;

	ret = kst_w_update(kst, idx, out, out_sz);

	if (ret == out_sz)
		return data_sz;
	else
		return ret;
#else
	return kst_w_update(kst, idx, data, data_sz);
#endif
}

static inline int ktkst_key_integrity(void)
{
#if KTKST_BACKUP
	int ret = 0;
	struct kst_t *kst = NULL;
#ifdef KTKST_INIT_FILE
	if (access(KTKST_INIT_FILE, F_OK) == 0)	// run once from boot
		return 0;
#endif
	kst = kst_r_init(KTKST_KEY_FILE, HASH_STR, HASH_STR_LEN);
	if (kst) {
		kst_deinit(kst);

		z_file_cmp_copy(KTKST_KEY_FILE, KTKST_KEY_FILE2, Z_FILE_OP_CMP_COPY, Z_FILE_EXEC_OP_BG);	// copy 0 to 1 if different, bg
		goto end;
	}

	kst = kst_r_init(KTKST_KEY_FILE2, HASH_STR, HASH_STR_LEN);
	if (kst) {
		kst_deinit(kst);

		z_file_cmp_copy(KTKST_KEY_FILE2, KTKST_KEY_FILE, Z_FILE_OP_COPY, Z_FILE_EXEC_OP_FG);	// copy 1 to 0 force
		goto end;
	}
	// all broken
	ret = -1;
 end:
#ifdef KTKST_INIT_FILE
	z_file_touch(KTKST_INIT_FILE);
#endif
	return ret;
#else
	return 0;
#endif
}

static int _ktkst_key_get(unsigned char *key1, unsigned char *key2, const unsigned char *key_default)
{
	struct kst_t *kst = NULL;
	int ret = 0;
	unsigned char _key_default[KTKST_KEY_LEN];

	if (!key_default) {
		memset(_key_default, 0, KTKST_KEY_LEN);
		key_default = _key_default;
	}

	kst = kst_r_init(KTKST_KEY_FILE, HASH_STR, HASH_STR_LEN);
	if (!kst) {
		if (key1)
			memcpy(key1, key_default, KTKST_KEY_LEN);
		if (key2)
			memcpy(key2, key_default, KTKST_KEY_LEN);
		return -100;
	}

	if (key1) {
		ret = _ktkst_get(kst, KTKST_IDX_KEY1, key1, KTKST_KEY_LEN);
		if (ret != KTKST_KEY_LEN) {
			memcpy(key1, key_default, KTKST_KEY_LEN);
			ret += -1;
		}
	}

	if (key2) {
		ret = _ktkst_get(kst, KTKST_IDX_KEY2, key2, KTKST_KEY_LEN);
		if (ret != KTKST_KEY_LEN) {
			memcpy(key2, key_default, KTKST_KEY_LEN);
			ret += -2;
		}
	}

	kst_deinit(kst);

	return ret;
}

__hidden int ktkst_key_get(unsigned char *key1, unsigned char *key2, const unsigned char *key_default)
{
	ktkst_key_integrity();

	return _ktkst_key_get(key1, key2, key_default);
}

__hidden int ktkst_key_new(unsigned char *key1, unsigned char *key2, const unsigned char *key_default)
{
	struct kst_t *kst = NULL;
	int ret = 0;
	unsigned char _key1[KTKST_KEY_LEN];
	unsigned char _key2[KTKST_KEY_LEN];
	unsigned char _key_default[KTKST_KEY_LEN];
	int err = 0;

	//ktkst_key_integrity();

	if (!key_default) {
		memset(_key_default, 0, KTKST_KEY_LEN);
		key_default = _key_default;
	}
	if (!key1)
		key1 = _key1;
	if (!key2)
		key2 = _key2;

	_ktkst_key_get(key2, NULL, key_default);

	kst = kst_w_init(KTKST_KEY_FILE, HASH_STR, HASH_STR_LEN);
	if (!kst) {
		memcpy(key1, key_default, KTKST_KEY_LEN);
		memcpy(key2, key_default, KTKST_KEY_LEN);
		return -100;
	}

	ret = _ktkst_update(kst, KTKST_IDX_KEY2, key2, KTKST_KEY_LEN);
	if (ret != KTKST_KEY_LEN) {
		memcpy(key2, key_default, KTKST_KEY_LEN);
		err += 2;
	}

	_random_key(key1, KTKST_KEY_LEN);

	ret = _ktkst_update(kst, KTKST_IDX_KEY1, key1, KTKST_KEY_LEN);
	if (ret != KTKST_KEY_LEN) {
		memcpy(key1, key_default, KTKST_KEY_LEN);
		err += 1;
	}

	kst_w_final(kst);
	kst_deinit(kst);

#if KTKST_BACKUP
	if (err == 0) {
		z_file_copy(KTKST_KEY_FILE, KTKST_KEY_FILE2);
#ifdef KT_SECURITY_FEATURE
		z_file_copy(KTKST_KEY2_FILE, KTKST_KEY2_FILE2);
#endif
	}
#endif

	return err;
}
