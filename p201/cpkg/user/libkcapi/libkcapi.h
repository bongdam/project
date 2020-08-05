#ifndef _CRYPTO_LINUX_H
#define _CRYPTO_LINUX_H

#include <stdint.h>

#ifndef __hidden
#define __hidden __attribute__((visibility("hidden")))
#endif

#ifdef __cplusplus
extern "C" {
#endif
/**
 * kcapi_md_sha256 - SHA-256 message digest on one buffer
 *
 * @in: [in] buffer with input data
 * @inlen: [in] length of input buffer
 * @out: [out] buffer for message digest
 * @outlen: [in] length of out
 *
 * With this one-shot convenience function, a message digest of the given buffer
 * is generated. The output buffer must be allocated by the caller and have at
 * least the length of the message digest size for the chosen message digest.
 *
 * @return size of message digest upon success;
 *	    -EIO - data cannot be obtained;
 * 	    -ENOMEM - buffer is too small for the complete message digest,
 * 	    the buffer is filled with the truncated message digest
 */
int32_t kcapi_md_sha256(const uint8_t *in, uint32_t inlen, uint8_t *out, uint32_t outlen);

/**
 * kcapi_cipher_enc_aes_cbc - Convenience function for AES CBC encryption
 *
 * @key: [in] key buffer
 * @keylen: [in] length of key buffer
 * @in: [in] plaintext data buffer
 * @inlen: [in] length of in buffer
 * @iv: [in] IV to be used for cipher operation
 * @out: [out] ciphertext data buffer
 * @outlen: [in] length of out buffer
 *
 * The convenience function performs an AES CBC encryption operation
 * using the provided key, the given input buffer and the given IV.
 * The output is stored in the out buffer.
 *
 * Note, AES CBC requires an input data that is a multiple of 16 bytes.
 * If you have data that is not guaranteed to be multiples of 16 bytes, either
 * add zero bytes at the end of the buffer to pad it up to a multiple of 16
 * bytes. Otherwise, the CTR mode encryption operation may be usable.
 *
 * The output buffer must be at least as large as the input buffer.
 *
 * The IV must be exactly 16 bytes in size.
 *
 * The AES type (AES-128, AES-192 or AES-256) is determined by the size
 * of the given key. If the key is 16 bytes long, AES-128 is used. A 24 byte
 * key implies AES-192 and a 32 byte key implies AES-256.
 *
 * @return number of bytes generated upon success;
 *	   a negative errno-style error code if an error occurred
 */
int32_t kcapi_cipher_enc_aes_cbc(const uint8_t *key, uint32_t keylen,
					  const uint8_t *in, uint32_t inlen, uint8_t *iv, uint8_t *out, uint32_t outlen);

/**
 * kcapi_cipher_dec_aes_cbc - Convenience function for AES CBC decryption
 *
 * @key: [in] key buffer
 * @keylen: [in] length of key buffer
 * @in: [in] ciphertext data buffer
 * @inlen: [in] length of in buffer
 * @iv: [in] IV to be used for cipher operation
 * @out: [out] plaintext data buffer
 * @outlen: [in] length of out buffer
 *
 * The convenience function performs an AES CBC decryption operation
 * using the provided key, the given input buffer and the given IV.
 * The output is stored in the out buffer.
 *
 * Note, AES CBC requires an input data that is a multiple of 16 bytes.
 * If you have data that is not guaranteed to be multiples of 16 bytes, either
 * add zero bytes at the end of the buffer to pad it up to a multiple of 16
 * bytes. Otherwise, the CTR mode encryption operation may be usable.
 *
 * The output buffer must be at least as large as the input buffer.
 *
 * The IV must be exactly 16 bytes in size.
 *
 * The AES type (AES-128, AES-192 or AES-256) is determined by the size
 * of the given key. If the key is 16 bytes long, AES-128 is used. A 24 byte
 * key implies AES-192 and a 32 byte key implies AES-256.
 *
 * @return number of bytes generated upon success;
 *	   a negative errno-style error code if an error occurred
 */
int32_t kcapi_cipher_dec_aes_cbc(const uint8_t *key, uint32_t keylen,
					  const uint8_t *in, uint32_t inlen, uint8_t *iv, uint8_t *out, uint32_t outlen);

#ifdef __cplusplus
}
#endif
#endif
