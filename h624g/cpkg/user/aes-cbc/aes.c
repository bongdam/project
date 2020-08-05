/*
 * aes.c
 * AES encrypt/decrypt wrapper functions used around Rijndael reference
 * implementation
 *
 * Copyright (C) 2009, Broadcom Corporation
 * All Rights Reserved.
 *
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: aes.c,v 1.2.10.1 2011-03-24 06:57:32 youngho Exp $
 */

#include "aes.h"

static inline void
xor_128bit_block(const uint8 *src1, const uint8 *src2, uint8 *dst)
{
	/* ARM CM3 rel time: 4668 (4191 if alignment check could be omitted) */
	int k;
	for (k = 0; k < 16; k++)
		dst[k] = src1[k] ^ src2[k];
}

/* AES-CBC mode encryption algorithm
 *	- handle partial blocks with padding of type as above
 *	- assumes nonce is ready to use as-is (i.e. any
 *		encryption/randomization of nonce/IV is handled by the caller)
 *	- ptxt and ctxt can point to the same location
 *	- returns -1 on error or final length of output
 */
int
BCMROMFN(aes_cbc_encrypt_pad)(uint32 *rk,
                              const size_t key_len,
                              const uint8 *nonce,
                              const size_t data_len,
                              const uint8 *ptxt,
                              uint8 *ctxt,
                              uint8 padd_type)
{
	uint8 tmp[AES_BLOCK_SZ];
	uint32 encrypt_len = 0;
	uint32 j;

	/* First block get XORed with nonce/IV */
	const unsigned char *iv = nonce;
	unsigned char *crypt_data = ctxt;
	const unsigned char *plain_data = ptxt;
	uint32 remaining = (uint32)data_len;

	while (remaining >= AES_BLOCK_SZ) {
		xor_128bit_block(iv, plain_data, tmp);
		aes_block_encrypt((int)AES_ROUNDS(key_len), rk, tmp, crypt_data);
		remaining -= AES_BLOCK_SZ;
		iv = crypt_data;
		crypt_data += AES_BLOCK_SZ;
		plain_data += AES_BLOCK_SZ;
		encrypt_len += AES_BLOCK_SZ;
	}

	if (padd_type == NO_PADDING)
		return encrypt_len;

	if (remaining) {
		for (j = 0; j < remaining; j++) {
			tmp[j] = plain_data[j] ^ iv[j];
		}
	}
	switch (padd_type) {
	case PAD_LEN_PADDING:
		for (j = remaining; j < AES_BLOCK_SZ; j++) {
			tmp[j] = (AES_BLOCK_SZ - remaining) ^  iv[j];
		}
		break;
	default:
		return -1;
	}

	aes_block_encrypt((int)AES_ROUNDS(key_len), rk, tmp, crypt_data);
	encrypt_len += AES_BLOCK_SZ;

	return (encrypt_len);
}

/* AES-CBC mode decryption algorithm
 *	- handle partial plaintext blocks with padding
 *	- ptxt and ctxt can point to the same location
 *	- returns -1 on error
 */
int
BCMROMFN(aes_cbc_decrypt_pad)(uint32 *rk,
                              const size_t key_len,
                              const uint8 *nonce,
                              const size_t data_len,
                              const uint8 *ctxt,
                              uint8 *ptxt,
                              uint8 padd_type)
{
	uint8 tmp[AES_BLOCK_SZ];
	uint32 remaining = (uint32)data_len;
	/* First block get XORed with nonce/IV */
	const unsigned char *iv = nonce;
	const unsigned char *crypt_data = ctxt;
	uint32 plaintext_len = 0;
	unsigned char *plain_data = ptxt;

	if (data_len % AES_BLOCK_SZ)
		return (-1);
	if (data_len < AES_BLOCK_SZ)
		return (-1);

	while (remaining >= AES_BLOCK_SZ) {
		aes_block_decrypt((int)AES_ROUNDS(key_len), rk, crypt_data, tmp);
		xor_128bit_block(tmp, iv, plain_data);
		remaining -= AES_BLOCK_SZ;
		iv = crypt_data;
		crypt_data += AES_BLOCK_SZ;
		plain_data += AES_BLOCK_SZ;
		plaintext_len += AES_BLOCK_SZ;
	}
	if (padd_type == PAD_LEN_PADDING)
		plaintext_len -= ptxt[plaintext_len - 1];
	return (plaintext_len);
}

#define AES_PUNIT (AES_BLOCK_SZ << 6)

int GIO_aes_cbc_encrypt(GIO *ig, GIO *og, uint8 *iv, uint8 *key)
{
	uint32 rk[4 * (AES_MAXROUNDS + 1)];
	uint8 in[AES_PUNIT], *out;
	ssize_t n, pos, output_len = 0;

	rijndaelKeySetupEnc(rk, key, AES_BLOCK_SZ * 8);
	out = in;
	for (pos = 0; (n = gio_safe_read(ig, in + pos, AES_PUNIT - pos)) > 0; ) {
		pos += n;
		if (pos < AES_PUNIT)
			continue;
		output_len += aes_cbc_encrypt_pad(rk, AES_BLOCK_SZ, iv, pos, in, out, NO_PADDING);
		gio_full_write(og, out, pos);
		pos = 0;
		memcpy(iv, &out[AES_PUNIT - AES_BLOCK_SZ], AES_BLOCK_SZ);
	}

	n = aes_cbc_encrypt_pad(rk, AES_BLOCK_SZ, iv, pos, in, out, PAD_LEN_PADDING);
	gio_full_write(og, out, n);
	return (output_len + n);
}

/*
	+------------------------------+---- out
	| for preventing IV corruption | 16
	+------------------------------+---- in
	|                              |  ^
	|                              |  |
	~                              ~  |
	|                              | 1024 (AES_PUNIT)
	|                              |  |
	+------------------------------+  |
	|              IV              |  |
	+------------------------------+  |
	|         length-encoded       |  v
	+------------------------------+-----

	The length-encoded area would be reserved for calling
	aes_cbc_decrypt_pad with PAD_LEN_PADDING argument
 */

int GIO_aes_cbc_decrypt(GIO *ig, GIO *og, uint8 *iv, uint8 *key)
{
	uint32 rk[4 * (AES_MAXROUNDS + 1)];
	uint8 buf[AES_PUNIT + AES_BLOCK_SZ];
	uint8 *in, *out;
	ssize_t n, pos, output_len = 0;

	rijndaelKeySetupDec(rk, key, AES_BLOCK_SZ * 8);
	out = buf;
	in = buf + AES_BLOCK_SZ;

	for (pos = 0; (n = gio_safe_read(ig, in + pos, AES_PUNIT - pos)) > 0; ) {
		pos += n;
		if (pos < AES_PUNIT)
			continue;
		output_len += aes_cbc_decrypt_pad(rk, AES_BLOCK_SZ, iv, pos - AES_BLOCK_SZ, in, out, NO_PADDING);
		gio_full_write(og, out, pos - AES_BLOCK_SZ);
		pos = AES_BLOCK_SZ;
		memcpy(iv, &in[AES_PUNIT - (AES_BLOCK_SZ << 1)], AES_BLOCK_SZ);
		memcpy(in, &in[AES_PUNIT - AES_BLOCK_SZ], AES_BLOCK_SZ);
	}

	n = aes_cbc_decrypt_pad(rk, AES_BLOCK_SZ, iv, pos, in, out, PAD_LEN_PADDING);
	gio_full_write(og, out, n);
	return (output_len + n);
}
