#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <openssl/aes.h>
#include "sys_lib.h"

#define MY_AES_KEY "P201 Product"
#define APDM_AES_IV "abcdefghijklmnopqrstuvwxyz"
#define APDM_AES_KEY_LEN 16

#define sys_malloc malloc
#define sys_free free

#define AES_BLOCK_SZ AES_BLOCK_SIZE


//////////////////////////////////////////////////////////////////////
// sys conf / operation
//////////////////////////////////////////////////////////////////////
static char *get_apdm_aes_key(void)
{
	return MY_AES_KEY;
}

//////////////////////////////////////////////////////////////////////
// encrypt/decrypt/auth
//////////////////////////////////////////////////////////////////////
static int sys_aes_cbc_dec(unsigned char *d, int dlen, unsigned char *e, int elen)
{
	unsigned char iv[APDM_AES_KEY_LEN];
	AES_KEY aeskey;
	int padding;
	int i;

	if (dlen < elen)
		return -1;

	if ((elen % AES_BLOCK_SZ) != 0)
		return -2;

	memcpy(iv, APDM_AES_IV, APDM_AES_KEY_LEN);
	AES_set_decrypt_key((unsigned char *)get_apdm_aes_key(), APDM_AES_KEY_LEN*8, &aeskey);
	AES_cbc_encrypt(e, d, elen, &aeskey, iv, AES_DECRYPT);

	// check padding
	padding = d[elen-1];
	if ((padding < 1) || (padding > AES_BLOCK_SZ))
		return -3;

	dlen = elen-padding;
	for (i = 0; i < padding; i++) {
		if (d[dlen+i] != padding)
			return -4;
	}

	return dlen;	// return original length
}

int sys_decrypt(unsigned char *e, int elen, int dbufsz)
{
	unsigned char *p;
	int ret;

	if (dbufsz < elen)
		return -1;
	p = (unsigned char *)sys_malloc(elen);
	if (!p)
		return -2;

	memcpy(p, e, elen);
	ret = sys_aes_cbc_dec(e, dbufsz, p, elen);
	sys_free(p);

	return ret;
}

static int sys_aes_cbc_enc(unsigned char *e, int elen, unsigned char *d, int dlen)
{
	unsigned char iv[APDM_AES_KEY_LEN];
	AES_KEY aeskey;
	int padding;
	int i;
	unsigned char *tmp;

	padding = AES_BLOCK_SZ - (dlen % AES_BLOCK_SZ);
	if (elen < (dlen + padding))
		return -1;

	tmp = (unsigned char *)malloc(dlen + padding);
	if (!tmp)
		return -2;

	// make padding to data
	memcpy(tmp, d, dlen);
	for (i = dlen; i < dlen + padding; i++)
		tmp[i] = (unsigned char)padding;

	memcpy(iv, APDM_AES_IV, APDM_AES_KEY_LEN);
	AES_set_encrypt_key((unsigned char *)get_apdm_aes_key(), APDM_AES_KEY_LEN * 8, &aeskey);
	AES_cbc_encrypt(tmp, e, dlen + padding, &aeskey, iv, AES_ENCRYPT);

	free(tmp);

	return dlen + padding;
}

int sys_encrypt(unsigned char *d, int dlen, int ebufsz)
{
	unsigned char *p;
	int ret;
	int padding;

	padding = AES_BLOCK_SZ - (dlen % AES_BLOCK_SZ);
	if (ebufsz < (dlen + padding))
		return -1;
	p = (unsigned char *)sys_malloc(dlen + padding);
	if (!p)
		return -2;

	memcpy(p, d, dlen);
	ret = sys_aes_cbc_enc(d, ebufsz, p, dlen);
	sys_free(p);

	return ret;
}
