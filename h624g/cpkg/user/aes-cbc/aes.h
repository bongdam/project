/*
 * aes.h
 * AES encrypt/decrypt wrapper functions used around Rijndael reference
 * implementation
 *
 * Copyright (C) 2009, Broadcom Corporation. All Rights Reserved.
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
 * $Id: aes.h,v 1.2.10.1 2011-03-24 07:23:14 youngho Exp $
 */

#ifndef _AES_H_
#define _AES_H_

#include "gio.h"
#include <stddef.h>
#include "rndl.h"

#define AES_BLOCK_SZ		16
#define AES_BLOCK_BITLEN	(AES_BLOCK_SZ * 8)
#define AES_KEY_BITLEN(kl)	((kl) * 8)
#define AES_ROUNDS(kl)		((AES_KEY_BITLEN(kl) / 32) + 6)
#define AES_MAXROUNDS		14

enum {
	NO_PADDING,
	PAD_LEN_PADDING /* padding with padding length  */
};

#define aes_block_encrypt(nr, rk, ptxt, ctxt)	rijndaelEncrypt(rk, nr, ptxt, ctxt)
#define aes_block_decrypt(nr, rk, ctxt, ptxt)	rijndaelDecrypt(rk, nr, ctxt, ptxt)

int
BCMROMFN(aes_cbc_encrypt_pad)(uint32 *rk, const size_t key_len, const uint8 *nonce,
                              const size_t data_len, const uint8 *ptxt, uint8 *ctxt,
                              uint8 pad_type);
int
BCMROMFN(aes_cbc_decrypt_pad)(uint32 *rk, const size_t key_len, const uint8 *nonce,
                              const size_t data_len, const uint8 *ctxt, uint8 *ptxt,
                              uint8 pad_type);

int GIO_aes_cbc_encrypt(GIO *ig, GIO *og, uint8 *iv, uint8 *key);
int GIO_aes_cbc_decrypt(GIO *ig, GIO *og, uint8 *iv, uint8 *key);

#endif /* _AES_H_ */
