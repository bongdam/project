/*
	Public domain by Andrew M. <liquidsun@gmail.com>

	Ed25519 reference implementation using Ed25519-donna
*/


/* define ED25519_SUFFIX to have it appended to the end of each public function */
#if !defined(ED25519_SUFFIX)
#define ED25519_SUFFIX 
#endif

#define ED25519_FN3(fn,suffix) fn##suffix
#define ED25519_FN2(fn,suffix) ED25519_FN3(fn,suffix)
#define ED25519_FN(fn)         ED25519_FN2(fn,ED25519_SUFFIX)

#include "ed25519-donna.h"
#include "ed25519.h"
#include "ed25519-randombytes.h"
#include "ed25519-hash.h"

#include <stdio.h>
#include <string.h>
//#include "test-ticks.h"
#include <stdlib.h>
#include "signature.h"

/*
	Generates a (extsk[0..31]) and aExt (extsk[32..63])
*/

#undef FAIL_CASE
#undef DEBUG
#ifdef DEBUG
#define SB_DBG prom_printf
#else
#define SB_DBG
#endif

DONNA_INLINE static void
ed25519_extsk(hash_512bits extsk, const ed25519_secret_key sk) {
	ed25519_hash(extsk, sk, 32);
	extsk[0] &= 248;
	extsk[31] &= 127;
	extsk[31] |= 64;
}

static void
ed25519_hram(hash_512bits hram, const ed25519_signature RS, const ed25519_public_key pk, const unsigned char *m, size_t mlen) {
	ed25519_hash_context ctx;
	ed25519_hash_init(&ctx);
	ed25519_hash_update(&ctx, RS, 32);
	ed25519_hash_update(&ctx, pk, 32);
	ed25519_hash_update(&ctx, m, mlen);
	ed25519_hash_final(&ctx, hram);
}

void
ED25519_FN(ed25519_publickey) (const ed25519_secret_key sk, ed25519_public_key pk) {
	bignum256modm a;
	ge25519 ALIGN(16) A;
	hash_512bits extsk;

	/* A = aB */
	ed25519_extsk(extsk, sk);
	expand256_modm(a, extsk, 32);
	ge25519_scalarmult_base_niels(&A, ge25519_niels_base_multiples, a);
	ge25519_pack(pk, &A);
}


void
ED25519_FN(ed25519_sign) (const unsigned char *m, size_t mlen, const ed25519_secret_key sk, const ed25519_public_key pk, ed25519_signature RS) {
	ed25519_hash_context ctx;
	bignum256modm r, S, a;
	ge25519 ALIGN(16) R;
	hash_512bits extsk, hashr, hram;

	ed25519_extsk(extsk, sk);

	/* r = H(aExt[32..64], m) */
	ed25519_hash_init(&ctx);
	ed25519_hash_update(&ctx, extsk + 32, 32);
	ed25519_hash_update(&ctx, m, mlen);
	ed25519_hash_final(&ctx, hashr);
	expand256_modm(r, hashr, 64);

	/* R = rB */
	ge25519_scalarmult_base_niels(&R, ge25519_niels_base_multiples, r);
	ge25519_pack(RS, &R);

	/* S = H(R,A,m).. */
	ed25519_hram(hram, RS, pk, m, mlen);
	expand256_modm(S, hram, 64);

	/* S = H(R,A,m)a */
	expand256_modm(a, extsk, 32);
	mul256_modm(S, S, a);

	/* S = (r + H(R,A,m)a) */
	add256_modm(S, S, r);

	/* S = (r + H(R,A,m)a) mod L */	
	contract256_modm(RS + 32, S);
}

int
ED25519_FN(ed25519_sign_open) (const unsigned char *m, size_t mlen, const ed25519_public_key pk, const ed25519_signature RS) {
	ge25519 ALIGN(16) R, A;
	hash_512bits hash;
	bignum256modm hram, S;
	unsigned char checkR[32];

	if ((RS[63] & 224) || !ge25519_unpack_negative_vartime(&A, pk))
		return -1;

	/* hram = H(R,A,m) */
	ed25519_hram(hash, RS, pk, m, mlen);
	expand256_modm(hram, hash, 64);

	/* S */
	expand256_modm(S, RS + 32, 32);

	/* SB - H(R,A,m)A */
	ge25519_double_scalarmult_vartime(&R, &A, hram, S);
	ge25519_pack(checkR, &R);

	/* check that R = SB - H(R,A,m)A */
	return ed25519_verify(RS, checkR, 32) ? 0 : -1;
}

#include "ed25519-donna-batchverify.h"

/*
	Fast Curve25519 basepoint scalar multiplication
*/

void
ED25519_FN(curved25519_scalarmult_basepoint) (curved25519_key pk, const curved25519_key e) {
	curved25519_key ec;
	bignum256modm s;
	bignum25519 ALIGN(16) yplusz, zminusy;
	ge25519 ALIGN(16) p;
	size_t i;

	/* clamp */
	for (i = 0; i < 32; i++) ec[i] = e[i];
	ec[0] &= 248;
	ec[31] &= 127;
	ec[31] |= 64;

	expand_raw256_modm(s, ec);

	/* scalar * basepoint */
	ge25519_scalarmult_base_niels(&p, ge25519_niels_base_multiples, s);

	/* u = (y + z) / (z - y) */
	curve25519_add(yplusz, p.y, p.z);
	curve25519_sub(zminusy, p.z, p.y);
	curve25519_recip(zminusy, zminusy);
	curve25519_mul(yplusz, yplusz, zminusy);
	curve25519_contract(pk, yplusz);
}

int ascii_to_hex(char c)
{
        int num = (int) c;
        if(num < 58 && num > 47)
        {
                return num - 48; 
        }
        if(num < 71 && num > 64)
        {
                return num - 55;
        }
	  if(num < 103 && num > 96)
        {
                return num - 87;
        }
        return num;
}

int verify_signature(int num, unsigned int image, unsigned int len, unsigned char *sig) 
{
	int ret_val = 1;
	unsigned char *public_key_string = {0};
	unsigned char public_key[32] = {0};
	unsigned char *data;
	unsigned char c1,c2;
	unsigned char sum;
	int i = 0;

	data = malloc(len);
	if( data == NULL ) {
		prom_printf("Error: unable to allocate required memory\n");
		return -1;
	}

	if (num == 1) {
		public_key_string = LINUX_PUB_KEY;
		prom_printf("verifying Linux signature... \n");
	} else if (num == 2) {
		public_key_string = ROOTFS_PUB_KEY;
		prom_printf("verifying rootfs signature... \n");
	}

	//prom_printf("public_key %s\n", public_key_string);
	SB_DBG("public_key: \n");
	for (i = 0; i < 32; i++) {
		c1 = ascii_to_hex(public_key_string[2*i]);
		c2 = ascii_to_hex(public_key_string[2*i + 1]);
		sum = c1<<4 | c2;
		public_key[i] = sum;
		SB_DBG("%02X",public_key[i]);
	}
	SB_DBG("\n\n");

	SB_DBG("signature: \n");
	for( i = 0; i < 64; i++) {
		SB_DBG("%02X", sig[i]);
		if (i == 31)
			SB_DBG("\n");
	}
	SB_DBG("\n\n");

	SB_DBG("len %x\n", len);
	SB_DBG("image addr: 0x%X \n", image);
	for (i = 0; i < len; i++) {
		data[i] = *(char*)(image + i);
	}

#ifdef DEBUG
	for (i = 0; i < 0x20; i++) {
		prom_printf("%02X ", data[i]);
		if (i == 0x0F)
			prom_printf("\n");
	}
	prom_printf("\n");
#endif
#ifdef FAIL_CASE  //check fail case
	prom_printf("Set wrong data to test fail case.\n");
	data[1] = data[1] + 1;
#endif
	ret_val = ed25519_sign_open(data, len, public_key, sig);

	if (ret_val!=0x0)
		prom_printf("Check signature fail\n");

	if (data != NULL)
		free(data);
	return ret_val;
}

