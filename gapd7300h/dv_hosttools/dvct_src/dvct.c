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

#define IN_TARGET 0
#define MAIN_INC 1
#define ENC_INC  1
#define DEC_INC  1
#define SUPPORT_OLD_FW 1

#if IN_TARGET
#include <fcntl.h>
#include <sys/ioctl.h>
#include "dvkif_ioctl.h"
#else
#define KEY "D@vO_Fw+zldls#zmflqtusd^mfdnlgks!*"
#define HASH_INIT_STR "fW&f1Rmw@re+Hash-Key#i$Money$9*HOw?MucH"
#endif
#define IV "abcdefghijklmnopqrstuvwxyz0123456789"

#define AES256_BLOCK_SIZE 16
#define SHA256_HASH_SIZE SHA256_DIGEST_LENGTH
#define AES_KEY_BIT 256
#define IV_LENGTH AES256_BLOCK_SIZE
#define FREAD_COUNT 1024
#define RW_SIZE 1


#define ROUND_UP(x, d) ( (((x)+((d)-1)) / (d)) * (d) )

#if ENC_INC || DEC_INC
static int file_size(FILE *fin)
{
	struct stat st;

	if (fstat(fileno(fin), &st)==0)
		return st.st_size;
	return 0;
}

static int sha256_file(FILE *fout, int off, int sz, unsigned char *hash, unsigned char *init_str)
{
	char buf[1024];
	int ret;
	int tlen=0;

	SHA256_CTX ctx;
	SHA256_Init(&ctx);

	if (init_str) {
		SHA256_Update(&ctx, init_str, strlen((void*)init_str));
	}

	fseek(fout, off, SEEK_SET);
	while ((ret=fread(buf, 1, 1024, fout))>0) {
		if (tlen+ret > sz) {
			ret = sz-tlen;
			if (ret < 0)
				break;
		}
		tlen += ret;
		SHA256_Update(&ctx, buf, ret);
	}
	SHA256_Final(hash, &ctx);

	return tlen;
}

static unsigned char *get_key(unsigned char *key, int szkey)
{
#if IN_TARGET
	dvkif_t data;
	int fd;
	unsigned char *p = key;

	fd = open("/proc/dvkif", O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Cannot open dvkif\n");
		return NULL;
	}

	data.code = 0;

	if (ioctl(fd, IOCTLDVKIF_STR_GET, &data)<0) {
		fprintf(stderr, "ioctl error\n");
		p = NULL;
	} else {
		//fprintf(stdout, "CODE 0 : [%s]\n", data.data);
		snprintf((char*)key, szkey, "%s", data.data);
		p = key;
	}

	close(fd);

	return p;
#else
	snprintf((char*)key, szkey, "%s", KEY);
	return key;
#endif
}

static unsigned char *get_hash_init_str(unsigned char *buf, int szbuf)
{
#if IN_TARGET
	dvkif_t data;
	int fd;
	unsigned char *p = buf;

	fd = open("/proc/dvkif", O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Cannot open dvkif\n");
		return NULL;
	}

	data.code = 1;

	if (ioctl(fd, IOCTLDVKIF_STR_GET, &data)<0) {
		fprintf(stderr, "ioctl error\n");
		p = NULL;
	} else {
		fprintf(stdout, "CODE 1 : [%s]\n", data.data);
		snprintf((char*)buf, szbuf, "%s", data.data);
		p = buf;
	}

	close(fd);

	return p;
#else
	snprintf((char*)buf, szbuf, "%s", HASH_INIT_STR);
	return buf;
#endif
}
#endif

#if ENC_INC
static void dvcontainer_mk_header(struct dvcontainer_t *p, FILE *fin, unsigned int product, unsigned int maj, unsigned int min, unsigned int bld)
{
	memset(p, 0, sizeof(*p));

	p->magic = DVCONTAINER_MAGIC;
	p->rand_block = 1;
	p->fw_start = sizeof(struct dvcontainer_t);
	p->fw_dec_size = file_size(fin);
	p->fw_size = ROUND_UP(p->fw_dec_size+(p->rand_block*AES256_BLOCK_SIZE)+1, AES256_BLOCK_SIZE);
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
static int aes_enc_file(unsigned char *key, FILE *fdec, FILE *fenc, int dec_len, int rand_h_sz)
{
	AES_KEY aes_key;
	unsigned char iv[32];
	unsigned char buf[RW_SIZE*FREAD_COUNT + AES256_BLOCK_SIZE];
	int len, padding_len;
	int tlen=0;

	memcpy(iv, IV, 32);

	AES_set_encrypt_key((void*)key, AES_KEY_BIT, &aes_key);

	// rand block
	if (rand_h_sz > 0) {
		if (rand_h_sz > sizeof(buf))
			return -40;
		for (len=0;len<rand_h_sz;len++)
			buf[len]=rand();
		AES_cbc_encrypt(buf, buf, rand_h_sz, &aes_key, iv, AES_ENCRYPT);
		fwrite(buf, RW_SIZE, rand_h_sz, fenc);
		tlen += rand_h_sz;
	}
	
	while ((len=fread(buf, RW_SIZE, FREAD_COUNT, fdec))) {
		if (len != FREAD_COUNT)
			break;
		AES_cbc_encrypt(buf, buf, len, &aes_key, iv, AES_ENCRYPT);
		fwrite(buf, RW_SIZE, len, fenc);
		tlen += len;
	}

	// padding 
	padding_len = AES256_BLOCK_SIZE - (len % AES256_BLOCK_SIZE);
	memset(buf+len, padding_len, padding_len);

	AES_cbc_encrypt(buf, buf, len+padding_len, &aes_key, iv, AES_ENCRYPT);
	fwrite(buf, RW_SIZE, len+padding_len, fenc);
	tlen += len+padding_len;

	//fprintf(stderr, "%s():%d dlen %d elen %d\n", __FUNCTION__, __LINE__, dec_len, tlen);

	return tlen;
}

static int output_encrypt_file(unsigned char *key, FILE *fout, FILE *fin, int inlen, int rand_h_sz)
{
	fseek(fout, 0, SEEK_END);
	return aes_enc_file(key, fin, fout, inlen, rand_h_sz);
}

static int output_hash(FILE *fout, int sz, unsigned char *hash_init_str)
{
	unsigned char hash[SHA256_HASH_SIZE];
	int ret;

	fseek(fout, 0, SEEK_SET);
	ret = sha256_file(fout, 0, sz, hash, hash_init_str);

	output_bytes(fout, (void *)hash, sizeof(hash));
	return ret;
}

int dvct_roll(char *infile, char *outfile, char *prod, unsigned int maj, unsigned int min, unsigned int bld)
{
	struct dvcontainer_t dvc_h;
	FILE *fin=NULL, *fout=NULL;
	int ret=0;
	unsigned char key[40];
	unsigned int product;
	unsigned char hash_init_str[80];

	product = strtoul(prod, NULL, 0);
	
	srand(time(NULL));

	if (get_key(key, sizeof(key))==NULL) {
		ret = -19;
		goto out;
	}

	if (get_hash_init_str(hash_init_str, sizeof(hash_init_str))==NULL) {
		ret = -29;
		goto out;
	}

	fin = fopen(infile, "r");
	fout = fopen(outfile, "w+");

	if (!fin || !fout) {
		fprintf(stderr, "cannot open file %p %p\n", fin, fout);
		ret = -10;
		goto out;
	}

	dvcontainer_mk_header(&dvc_h, fin, product, maj, min, bld);
	output_bytes(fout, (void *)&dvc_h, sizeof(dvc_h));
	
	if (output_encrypt_file(key, fout, fin, dvc_h.fw_dec_size, dvc_h.rand_block*AES256_BLOCK_SIZE)!=dvc_h.fw_size) {
		fprintf(stderr, "enc err\n");
		ret = -11;
		goto out;
	}

	if (output_hash(fout, dvc_h.fw_size+sizeof(dvc_h), hash_init_str)!=dvc_h.fw_size+sizeof(dvc_h)) {
		fprintf(stderr, "hash err\n");
		ret = -12;
		goto out;
	}

out:
	if (fin) fclose(fin);
	if (fout) fclose(fout);
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
static int aes_dec_file(unsigned char *key, FILE *fp, FILE *fout, int enc_off, int enc_len, int dec_off, int rand_h_sz)
{
	AES_KEY aes_key;
	unsigned char iv[IV_LENGTH];
	unsigned int tlen=0, wlen=0;
	unsigned char buf[RW_SIZE*FREAD_COUNT + AES256_BLOCK_SIZE];
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
		len=fread_from_off(buf, RW_SIZE, read_sz, fp, enc_off);
		remaining_sz -= len;

		enc_off += len;
		tlen += len;
		AES_cbc_encrypt(buf, buf, len, &aes_key, iv, AES_DECRYPT);
		if (tlen >= enc_len) {
			len -= buf[len-1];
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

static int dvcontainer_get_header(struct dvcontainer_t *p, FILE *fp, int fsz)
{
	int ret;
	
	ret = fread(p, 1, sizeof(struct dvcontainer_t), fp);
	if (ret != sizeof(struct dvcontainer_t))
		return -1;

	// validation
	if (!dvct_is_magic(p)) 
		return -2;

	if (p->product != dvct_product())
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

static int validate_hash(FILE *fp, int sz, int hash_start, unsigned char *hash_init_str)
{
	unsigned char f_hash[SHA256_HASH_SIZE];
	unsigned char c_hash[SHA256_HASH_SIZE];
	int ret;
	
	// get hash from file
	fseek(fp, hash_start, SEEK_SET);
	ret = fread(f_hash, 1, SHA256_HASH_SIZE, fp);
	if (ret != SHA256_HASH_SIZE)
		return -1;

	// calc hash
	ret = sha256_file(fp, 0, sz, c_hash, hash_init_str);
	if (ret != sz) {
		//fprintf(stderr, "%s():%d ret %d sz %d\n", __FUNCTION__, __LINE__, ret, sz);
		return -2;
	}
	
	if (memcmp(f_hash, c_hash, SHA256_HASH_SIZE)!=0)
		return -3;

	return 0;
}

static int dec_file(unsigned char *key, FILE *fp, int in_off, int sz, int out_off, int out_sz_h, int rand_h_sz)
{
	int ret;

	ret = aes_dec_file(key, fp, NULL, in_off, sz, out_off, rand_h_sz);
	if (ret != out_sz_h) 
		return -1;

	ftruncate(fileno(fp), out_sz_h);
	return 0;
}

int dvct_unroll(char *fname)
{
	FILE *fp=NULL;
	int ret=0;;
	struct dvcontainer_t dvc_h;
	unsigned char hash_init_str[80];
	int fsz=0;
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
	if ((ret=dvcontainer_get_header(&dvc_h, fp, fsz))!=0) {
#if SUPPORT_OLD_FW
		if (ret == -2) { // magic error
			ret = 0;
			goto out;
		}
#endif
		ret += -20;
		goto out;
	}

	if (get_key(key, sizeof(key))==NULL) {
		ret = -29;
		goto out;
	}

	if (get_hash_init_str(hash_init_str, sizeof(hash_init_str))==NULL) {
		ret = -28;
		goto out;
	}

	if ((ret=validate_hash(fp, dvc_h.fw_size+sizeof(dvc_h), dvc_h.hash_start, hash_init_str))!=0) {
		ret += -30;
		goto out;
	}

	if ((ret=dec_file(key, fp, dvc_h.fw_start, dvc_h.fw_size, 0, dvc_h.fw_dec_size, dvc_h.rand_block*AES256_BLOCK_SIZE))!=0) {
		ret += -40;
		goto out;
	}
out:
	if (fp) fclose(fp);

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

	return dvct_roll(argv[1], argv[2], argv[3], atoi(argv[4]), atoi(argv[5]), atoi(argv[6]));
#else
	return -100;
#endif
}

static int unroll_main(int argc, char *argv[])
{
#if DEC_INC
	if (argc < 2) {
		fprintf(stderr, "Arg needed, file to unroll\n");
		return -1;
	}

	return dvct_unroll(argv[1]);
#else
	return -100;
#endif
}

int main(int argc, char *argv[])
{
	if (strstr(argv[0],"dvct_unroll"))
		return unroll_main(argc, argv);
	return roll_main(argc, argv);
}
#endif

