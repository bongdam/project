#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <openssl/aes.h>

#include "libdvct.h"

#define MAIN_INC 1
#define ENC_INC  1
#define DEC_INC  1
#define SUPPORT_OLD_FW 0
#define DBG 0

// rJ//CjHcZ=SuMU?lm/a&bakC,vG*@Dvq
static unsigned char KEY[] = {
	0xb1, 0x72, 0x8d, 0x3b, 0x0, 0x75, 0xe1, 0x52, 
	0xf8, 0x6a, 0xaa, 0x3f, 0x98, 0x65, 0xfe, 0x33, 
	0xf0, 0x3d, 0x4f, 0x66, 0x25, 0x9d, 0xa0, 0x73, 
	0x51, 0xb, 0x54, 0xbe, 0x8, 0x16, 0xeb, 0x71, 
	0xfe
};

// BOM&Y=D=j)f.UdVH(9ft%gkjRr6n%-+8=)d,#/x;yagbrmLJ^/_FXHm*f,q%3GY$
static unsigned char HASH_INIT_STR[] = {
	0x65, 0x9b, 0xde, 0x31, 0x60, 0x75, 0xf, 0xdc,
	0xd3, 0x91, 0xca, 0x1f, 0x6a, 0xeb, 0xac, 0xc,
	0xd4, 0xf2, 0xa9, 0xd0, 0xeb, 0xe7, 0x7f, 0x8d,
	0xa2, 0xab, 0x2a, 0xa4, 0x4e, 0x9e, 0xc1, 0x68,
	0xbe, 0x46, 0x7a, 0xeb, 0x5c, 0x51, 0xa2, 0xe8,
	0xf9, 0xa, 0x46, 0xa0, 0x5d, 0x9b, 0xc7, 0x0,
	0xf1, 0x8f, 0x70, 0x3d, 0x2e, 0x4a, 0x4b, 0x6,
	0xff, 0x8f, 0x46, 0x1d, 0x5a, 0x42, 0x26, 0x38,
	0xf1
};

#define IV "abcdefghijklmnopqrstuvwxyz0123456789"

#define AES256_BLOCK_SIZE 16
#define SHA256_HASH_SIZE SHA256_DIGEST_LENGTH
#define AES_KEY_BIT 256
#define IV_LENGTH AES256_BLOCK_SIZE
#define FREAD_COUNT 1024
#define RW_SIZE 1

#define ROUNDUP(x, y) \
({							\
	const typeof(y) __y = y;			\
	(((x) + (__y - 1)) / __y) * __y;		\
})

#define min(x, y) ({				\
	typeof(x) _min1 = (x);			\
	typeof(y) _min2 = (y);			\
	(void) (&_min1 == &_min2);		\
	_min1 < _min2 ? _min1 : _min2; })

#if ENC_INC || DEC_INC
static int file_size(FILE *f)
{
	struct stat st;
	if (fstat(fileno(f), &st) == 0)
		return st.st_size;
	return 0;
}

#if DBG
void dump(char *banner, unsigned char *p, int sz)
{
	int i;

	fprintf(stderr, "---- %s  (%d)------\n", banner, sz);
	for (i = 0; i < sz; i++) {
		fprintf(stderr, "%02X ", p[i]);
	}
	fprintf(stderr, "\n");
}
#else
#define dump(...)
#endif

static size_t sha256_file(FILE *f, long off, size_t sz, unsigned char *hash, char *salt)
{
	char buf[1024];
	size_t n, count = 0;
	SHA256_CTX ctx;

	if (fseek(f, off, SEEK_SET) < 0) {
		perror(__func__);
		return 0;
	}
	SHA256_Init(&ctx);
	if (salt)
		SHA256_Update(&ctx, salt, strlen(salt));
	while (sz && (n = fread(buf, 1, min(sizeof(buf), sz), f))) {
		SHA256_Update(&ctx, buf, n);
		count += n;
		sz -= n;
	}
	SHA256_Final(hash, &ctx);
	return count;
}

static unsigned char *get_key(unsigned char *key, int szkey)
{
	snprintf((char *)key, szkey, "%s", (char *)KEY);
	return key;
}

static char *get_hash_init_str(char *buf, int szbuf)
{
	snprintf(buf, szbuf, "%s", (char *)HASH_INIT_STR);
	return buf;
}
#endif

#if ENC_INC
static void dvcontainer_mk_header(struct dvcontainer_t *p, FILE *f,
                                  unsigned int product, unsigned int maj,
                                  unsigned int min, unsigned int bld)
{
	memset(p, 0, sizeof(*p));

	p->magic = DVCONTAINER_MAGIC;
	p->rand_block = 1;
	p->fw_start = sizeof(struct dvcontainer_t);
	p->fw_dec_size = file_size(f);
	p->fw_size = ROUNDUP(p->fw_dec_size + (p->rand_block * AES256_BLOCK_SIZE) + 1, AES256_BLOCK_SIZE);
	p->hash_start = p->fw_start + p->fw_size;
	p->hash_size = SHA256_HASH_SIZE;
	p->product = product;
	p->version = dvct_version(maj, min, bld);
}

static void output_bytes(FILE *fout, unsigned char *p, int len)
{
	fseek(fout, 0, SEEK_END);
	fwrite(p, len, 1, fout);
}

/*
 * aes_enc_file : encrypt full fdec contents to fenc.
 *      fdec - file pointer to be encrypted
 *      fenc - file pointer for encrypted
 *      dec_len - fdec file size (not used)
 *      rand_h_sz - random block bytes, add random block at the top of fenc(for increasing randomness)
 */
static int aes_enc_file(unsigned char *key, FILE *fdec, FILE *fenc,
                        int dec_len, int rand_h_sz)
{
	AES_KEY aes_key;
	unsigned char iv[32];
	unsigned char buf[RW_SIZE * FREAD_COUNT + AES256_BLOCK_SIZE];
	int len, padding_len;
	int tlen = 0;

	memcpy(iv, IV, 32);

	AES_set_encrypt_key((void *)key, AES_KEY_BIT, &aes_key);

	// rand block
	if (rand_h_sz > 0) {
		if (rand_h_sz > sizeof(buf))
			return -40;
		for (len = 0; len < rand_h_sz; len++)
			buf[len] = rand();
		AES_cbc_encrypt(buf, buf, rand_h_sz, &aes_key, iv, AES_ENCRYPT);
		fwrite(buf, RW_SIZE, rand_h_sz, fenc);
		tlen += rand_h_sz;
	}

	while ((len = fread(buf, RW_SIZE, FREAD_COUNT, fdec))) {
		if (len != FREAD_COUNT)
			break;
		AES_cbc_encrypt(buf, buf, len, &aes_key, iv, AES_ENCRYPT);
		fwrite(buf, RW_SIZE, len, fenc);
		tlen += len;
	}

	// padding
	padding_len = AES256_BLOCK_SIZE - (len % AES256_BLOCK_SIZE);
	memset(buf + len, padding_len, padding_len);

	AES_cbc_encrypt(buf, buf, len + padding_len, &aes_key, iv, AES_ENCRYPT);
	fwrite(buf, RW_SIZE, len + padding_len, fenc);
	tlen += len + padding_len;

	return tlen;
}

static int output_encrypt_file(unsigned char *key, FILE *fout, FILE *fin,
                               int inlen, int rand_h_sz)
{
	fseek(fout, 0, SEEK_END);
	return aes_enc_file(key, fin, fout, inlen, rand_h_sz);
}

static int output_hash(FILE *fout, int sz, char *hash_init_str)
{
	unsigned char hash[SHA256_HASH_SIZE];
	int ret;

	fseek(fout, 0, SEEK_SET);
	ret = sha256_file(fout, 0, sz, hash, hash_init_str);

	dump("output_hash", hash, sizeof(hash));
	output_bytes(fout, (void *)hash, sizeof(hash));
	return ret;
}

int dvct_roll(char *infile, char *outfile, char *prod, unsigned int maj,
              unsigned int min, unsigned int bld)
{
	struct dvcontainer_t dvc_h;
	FILE *fin = NULL, *fout = NULL;
	int ret = 0;
	unsigned char key[40];
	unsigned int product;
	char hash_init_str[80];

	product = strtoul(prod, NULL, 0);

	srand(time(NULL));

	if (get_key(key, sizeof(key)) == NULL) {
		ret = -19;
		goto out;
	}

	if (get_hash_init_str(hash_init_str, sizeof(hash_init_str)) == NULL) {
		ret = -29;
		goto out;
	}

	fin = fopen(infile, "r");
	if (strcmp(outfile, "-"))
		fout = fopen(outfile, "w+");
	else
		fout = stdout;

	if (!fin || !fout) {
		fprintf(stderr, "cannot open file %p %p\n", fin, fout);
		ret = -10;
		goto out;
	}

	dvcontainer_mk_header(&dvc_h, fin, product, maj, min, bld);
	output_bytes(fout, (void *)&dvc_h, sizeof(dvc_h));

	if (output_encrypt_file(key, fout, fin, dvc_h.fw_dec_size, dvc_h.rand_block * AES256_BLOCK_SIZE) != dvc_h.fw_size) {
		fprintf(stderr, "enc err\n");
		ret = -11;
		goto out;
	}

	if (output_hash(fout, dvc_h.fw_size + sizeof(dvc_h), hash_init_str) != dvc_h.fw_size + sizeof(dvc_h)) {
		fprintf(stderr, "hash err\n");
		ret = -12;
		goto out;
	}

out:
	if (fin)
		fclose(fin);
	if (fout != stdout)
		fclose(fout);
	return ret;
}
#endif

#if DEC_INC
static int fread_from_off(unsigned char *buf, int e_sz, int e_num, FILE *fp, int off)
{
	fseek(fp, off, SEEK_SET);
	return fread(buf, e_sz, e_num, fp);
}

static int fwrite_to_off(unsigned char *buf, int e_sz, int e_num, FILE *fp, int off)
{
	fseek(fp, off, SEEK_SET);
	return fwrite(buf, e_sz, e_num, fp);
}

/*
 * aes_dec_file : decrypt fp to fout, if fout is NULL, same file is used for decrypted output
 *      fp - file pointer to be decrypted
 *      fout - file pointer for decrypted output, if NULL, fp is used for decrypted output
 *      enc_off - encrypted contents start offset in fp
 *      enc_len - encrypted contents length in fp
 *      dec_off - decrypted contents start offset in fout, decrypted output will be written from the dec_off
 *      rand_h_sz - random block bytes, random block bytes to be stripped off when writing decrypted output
 */
static int aes_dec_file(unsigned char *key, FILE *fp, FILE *fout, int enc_off,
                        int enc_len, int dec_off, int rand_h_sz)
{
	AES_KEY aes_key;
	unsigned char iv[IV_LENGTH];
	unsigned int tlen = 0, wlen = 0;
	unsigned char buf[RW_SIZE * FREAD_COUNT + AES256_BLOCK_SIZE];
	int len;
	int remaining_sz = enc_len;

	if (!fout)
		fout = fp;

	memcpy(iv, IV, IV_LENGTH);

	//fprintf(stderr, "%s():%d enc_len %d enc_off %d dec_off %d\n", __FUNCTION__, __LINE__, enc_len, enc_off, dec_off);
	AES_set_decrypt_key((void *)key, AES_KEY_BIT, &aes_key);

	while (remaining_sz > 0) {
		int read_sz;
		int buf_off;

		read_sz = (remaining_sz > FREAD_COUNT) ? FREAD_COUNT : remaining_sz;
		len = fread_from_off(buf, RW_SIZE, read_sz, fp, enc_off);
		remaining_sz -= len;

		enc_off += len;
		tlen += len;
		AES_cbc_encrypt(buf, buf, len, &aes_key, iv, AES_DECRYPT);
		if (tlen >= enc_len) {
			len -= buf[len - 1];
		}

		buf_off = 0;
		if (rand_h_sz > 0) {
			if (len > rand_h_sz) {
				len -= rand_h_sz;
				buf_off = rand_h_sz;
				rand_h_sz = 0;
			} else {
				rand_h_sz -= len;
				len = 0;
			}
		}
		if (len > 0) {
			fwrite_to_off(&buf[buf_off], RW_SIZE, len, fout, dec_off);
			dec_off += len;
			wlen += len;
		}
	}
	//fprintf(stderr, "%s():%d wlen %d\n", __FUNCTION__, __LINE__, wlen);
	return wlen;
}

static unsigned int endian_change_4(unsigned int a)
{
	return ((a >> 24) & 0x000000ff) | ((a >> 8) & 0x0000ff00) | ((a << 8) & 0x00ff0000) | ((a << 24) & 0xff000000);
}

#define ENDIAN_CHANGE_4(x) do{x = endian_change_4(x);} while(0)

static int dvcontainer_get_header(struct dvcontainer_t *p, FILE *fp, int fsz, unsigned int prod)
{
	int ret;

	ret = fread(p, 1, sizeof(struct dvcontainer_t), fp);
	if (ret != sizeof(struct dvcontainer_t))
		return -1;

	// validation
	if (!dvct_is_magic(p)) {
		ENDIAN_CHANGE_4(p->magic);
		if (dvct_is_magic(p)) {
			ENDIAN_CHANGE_4(p->fw_start);
			ENDIAN_CHANGE_4(p->fw_dec_size);
			ENDIAN_CHANGE_4(p->fw_size);
			ENDIAN_CHANGE_4(p->hash_start);
			ENDIAN_CHANGE_4(p->hash_size);
			ENDIAN_CHANGE_4(p->rand_block);
			ENDIAN_CHANGE_4(p->product);
			ENDIAN_CHANGE_4(p->version);
		} else {
			return -2;
		}
	}

	if (p->product != prod)
		return -3;

	if ((p->hash_start + p->hash_size) != fsz)
		return -4;

	if (p->fw_start < sizeof(struct dvcontainer_t))
		return -5;

	if ((p->fw_start + p->fw_size) > p->hash_start)
		return -6;

	if (p->fw_size < p->fw_dec_size)
		return -7;

	if (p->hash_size != SHA256_HASH_SIZE)
		return -8;

	return 0;
}

static int validate_hash(FILE *fp, int sz, int hash_start, char *hash_init_str)
{
	unsigned char f_hash[SHA256_HASH_SIZE];
	unsigned char c_hash[SHA256_HASH_SIZE];
	int ret;

	// get hash from file
	fseek(fp, hash_start, SEEK_SET);
	ret = fread(f_hash, 1, SHA256_HASH_SIZE, fp);
	if (ret != SHA256_HASH_SIZE)
		return -1;

	dump("validate_hash f_hash", f_hash, sizeof(f_hash));
	// calc hash
	ret = sha256_file(fp, 0, sz, c_hash, hash_init_str);
	if (ret != sz) {
		//fprintf(stderr, "%s():%d ret %d sz %d\n", __FUNCTION__, __LINE__, ret, sz);
		return -2;
	}

	dump("validate_hash c_hash", c_hash, sizeof(c_hash));
	if (memcmp(f_hash, c_hash, SHA256_HASH_SIZE) != 0)
		return -3;

	return 0;
}

static int dec_file(unsigned char *key, FILE *fp, int in_off, int sz,
                    int out_off, int out_sz_h, int rand_h_sz)
{
	int ret;

	ret = aes_dec_file(key, fp, NULL, in_off, sz, out_off, rand_h_sz);
	if (ret != out_sz_h)
		return -1;

	ftruncate(fileno(fp), out_sz_h);
	return 0;
}

int dvct_unroll(char *fname, unsigned int prod, int validcheck_only)
{
	FILE *fp = NULL;
	int ret = 0;;
	struct dvcontainer_t dvc_h;
	char hash_init_str[80];
	int fsz = 0;
	unsigned char key[40];

	fp = fopen(fname, "r+");
	if (!fp) {
		ret = -10;
		goto out;
	}

	fsz = file_size(fp);
	if (fsz < sizeof(struct dvcontainer_t)) {
		ret = -11;
		goto out;
	}

	fseek(fp, 0, SEEK_SET);
	if ((ret = dvcontainer_get_header(&dvc_h, fp, fsz, prod)) != 0) {
#if SUPPORT_OLD_FW
		if (ret == -2) {	// magic error
			ret = 0;
			goto out;
		}
#endif
		ret += -20;
		goto out;
	}

	if (get_key(key, sizeof(key)) == NULL) {
		ret = -29;
		goto out;
	}

	if (get_hash_init_str(hash_init_str, sizeof(hash_init_str)) == NULL) {
		ret = -28;
		goto out;
	}

	if ((ret = validate_hash(fp, dvc_h.fw_size + sizeof(dvc_h), dvc_h.hash_start, hash_init_str)) != 0) {
		ret += -30;
		goto out;
	}

	if (validcheck_only) {
		ret = 0;
		goto out;
	}

	if ((ret = dec_file(key, fp, dvc_h.fw_start, dvc_h.fw_size, 0,
			dvc_h.fw_dec_size,
			dvc_h.rand_block * AES256_BLOCK_SIZE)) != 0) {
		ret += -40;
		goto out;
	}
out:
	if (fp)
		fclose(fp);

	//fprintf(stderr, "%s():%d ret %d\n", __FUNCTION__, __LINE__, ret);
	return ret;
}
#endif

#if MAIN_INC
static int roll_main(int argc, char *argv[])
{
#if ENC_INC
	if (argc < 7) {
		fprintf(stderr, "Arg needed, input output model maj min bld\n");
		return -1;
	}

	return dvct_roll(argv[1], argv[2], argv[3], atoi(argv[4]),
	                 atoi(argv[5]), atoi(argv[6]));
#else
	return -100;
#endif
}

static int unroll_main(int argc, char *argv[])
{
#if DEC_INC
	int ret;
	if (argc < 3) {
		fprintf(stderr, "Arg needed, file to unroll\n");
		return -1;
	}

	ret = dvct_unroll(argv[1], strtoul(argv[2], NULL, 0), 0);
#if DBG
	printf("dvct_unroll return %d\n", ret);
#endif
	return ret;
#else
	return -100;
#endif
}

static int validcheck_main(int argc, char *argv[])
{
#if DEC_INC
	int ret;
	if (argc < 3) {
		fprintf(stderr, "Arg needed, file to unroll\n");
		return -1;
	}

	ret = dvct_unroll(argv[1], strtoul(argv[2], NULL, 0), 1);
#if DBG
	printf("dvct_unroll return %d\n", ret);
#endif
	return ret;
#else
	return -100;
#endif
}

int main(int argc, char *argv[])
{
	if (strstr(argv[0], "dvct_unroll"))
		return unroll_main(argc, argv);
	if (strstr(argv[0], "dvct_validcheck"))
		return validcheck_main(argc, argv);
	return roll_main(argc, argv);
}
#endif

static void __attribute__ ((constructor)) dvct_obfuscator(void)
{
	unsigned char c;
	int m;

	for (m = 0; m < sizeof(HASH_INIT_STR); ++m) {
		c = HASH_INIT_STR[m];
		c = (c >> 0x6) | (c << 0x2);
		c = ~c;
		c -= 0x85;
		c ^= m;
		c -= 0x52;
		c = -c;
		c ^= 0x76;
		c = (c >> 0x3) | (c << 0x5);
		c -= 0xbd;
		c = -c;
		c -= m;
		c ^= m;
		c -= m;
		c ^= 0x18;
		c += m;
		HASH_INIT_STR[m] = c;
	}
	for (m = 0; m < sizeof(KEY); ++m)
	{
		c = KEY[m];
		c -= 0x3e;
		c ^= m;
		c -= 0x6;
		c = (c >> 0x6) | (c << 0x2);
		c ^= m;
		c -= m;
		c ^= 0x91;
		c += m;
		c ^= m;
		c -= 0x13;
		c ^= 0x3a;
		c += 0x23;
		c = (c >> 0x5) | (c << 0x3);
		c ^= m;
		c -= m;
		KEY[m] = c;
	}
}