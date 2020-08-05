#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <stdint.h>
#include "crypto_linux.h"
#include "kst.h"
#include "file_utils.h"

/* kst(key storage) interface */

/*
 * layout of storage
 *
 * +-----------------+ <-- 0
 * | HASH 512 (64B)  |
 * +-----------------+ <--
 * | INDEX (32B/16B) |
 * | (Start PTR)     |
 * | (save 16 PTRs)  |
 * +-----------------+ <--
 * |                 |
 * |                 |
 * | Storage Area    |
 * |  (ARENA)        |
 * |                 |
 * |                 |
 * +-----------------+ <--
 *
 */

#if defined(KST_2B_PTR)
#define KST_TOTAL_SIZE    1024
#else
#define KST_TOTAL_SIZE    256	/* 1B ptr max size is 256B */
#endif
#define KST_HASH_SIZE     (256/8)
#define KST_INDEX_MAX     16
#define KST_INDEX_SIZE    (KST_INDEX_MAX*sizeof(index_type))

#define KST_HASH_OFFSET   0	//(KST_TOTAL_SIZE - KST_HASH_SIZE)
#define KST_INDEX_OFFSET  KST_HASH_SIZE
#define KST_ARENA_OFFSET  (KST_INDEX_OFFSET+KST_INDEX_SIZE)

#define KST_ARENA_SIZE    (KST_TOTAL_SIZE-KST_ARENA_OFFSET)

#define MAX_HASH_STR 64
static unsigned char _hash_str[MAX_HASH_STR];
static int _hash_str_len;

static inline void do_srand(void)
{
	static int first = 1;
	if (first) {
		srand(time(NULL));
		first = 0;
	}
}

__hidden void kst_rand_str_get(void *_p, int n)
{
	unsigned char *p = _p;
	int fd;

	fd = open("/dev/urandom", O_RDONLY);
	if (fd >= 0) {
		z_safe_read(fd, p, n);
		close(fd);
	} else {
		int i;

		do_srand();

		for (i = 0; i < n; i++)
			p[i] = rand();
	}
}

static inline unsigned int my_rand(void)
{
	unsigned int rnd;
	kst_rand_str_get(&rnd, sizeof(rnd));
	return rnd;
}

static inline int rand_from(int start, int max)
{
	int n;
	// return start <= ret < max
	n = max - start;
	return (my_rand() % n) + start;

}

static inline void swap(index_type * array, int a, int b)
{
	index_type t;
	if (a == b)
		return;
	t = array[a];
	array[a] = array[b];
	array[b] = t;
}

static void shuffle(index_type * array, int n)
{
	int i, j;

	for (i = 0; i < n - 1; i++) {
		j = rand_from(i, n);
		swap(array, i, j);
	}
}

/*
 * rseq(random sequence) data
 *  - shuffle data area, and get one by one from the first
 */

static void rseq_init(struct rseq_t *r, index_type * a, int n)
{
	r->i = 0;
	r->a = a;
	r->n = n;		// length of a

	shuffle(a, n);
}

static int rseq_get(struct rseq_t *r)
{
	if (r->i >= r->n)
		return -1;
	return r->a[(r->i)++];
}

static int index_get(void *_p, int i, int max)
{
	index_type a;
	index_type *p = _p;
	memcpy(&a, &(p[i]), sizeof(index_type));

	return a % max;
}

static void index_set(void *_p, int i, int d, int max)
{
	index_type a;
	index_type *p = _p;
	unsigned int type_div;

	switch (sizeof(index_type)) {
	case 1:
		type_div = 0;
		break;
	default:
		type_div = 0x10000UL / (unsigned int)max;
		break;
	}

	if (type_div > 0) {
		// randomize d
		d = d + ((my_rand() % type_div)) * max;
	}
	a = d;

	memcpy(&(p[i]), &a, sizeof(index_type));
}

static void __hash_generate(unsigned char *d, int d_sz, unsigned char out[KST_HASH_SIZE])
{
	void *p;

	if (!posix_memalign(&p, sysconf(_SC_PAGESIZE), _hash_str_len + d_sz)) {
		memcpy(p, _hash_str, _hash_str_len);
		memcpy(p + _hash_str_len, d, d_sz);
		kcapi_md_sha256(p, _hash_str_len + d_sz, out, KST_HASH_SIZE);
		free(p);
	}
}

static int kst_hash_validate(struct kst_t *kst)
{
	unsigned char hash[KST_HASH_SIZE];

	__hash_generate(&kst->data[KST_INDEX_OFFSET], KST_TOTAL_SIZE - KST_HASH_SIZE, hash);
	return (memcmp(&kst->data[KST_HASH_OFFSET], hash, KST_HASH_SIZE) == 0) ? 1 : 0;
}

static void kst_hash_generate(struct kst_t *kst)
{
	unsigned char hash[KST_HASH_SIZE];

	__hash_generate(&kst->data[KST_INDEX_OFFSET], KST_TOTAL_SIZE - KST_HASH_SIZE, hash);
	memcpy(&kst->data[KST_HASH_OFFSET], hash, KST_HASH_SIZE);
}

static inline int kst_index_eol(void)
{
	return rand_from(KST_HASH_OFFSET, KST_ARENA_OFFSET);
}

static inline int kst_index_is_eol(index_type a)
{
	return (a < KST_ARENA_OFFSET);
}

static void kst_free(struct kst_t *kst)
{
	if (!kst)
		return;

	if (kst->fname)
		free(kst->fname);
	if (kst->data)
		free(kst->data);
	if (kst->rseq_data)
		free(kst->rseq_data);
	free(kst);
}

static struct kst_t *kst_alloc(char *fname)
{
	struct kst_t *kst;

	kst = (struct kst_t *)malloc(sizeof(struct kst_t));
	if (!kst)
		return NULL;

	memset(kst, 0, sizeof(struct kst_t));
	kst->fname = strdup(fname);
	if (!kst->fname)
		goto err_end;
	kst->data_sz = KST_TOTAL_SIZE;
	kst->data = (unsigned char *)malloc(kst->data_sz);
	if (!kst->data)
		goto err_end;
	kst->f_exist = 0;

	return kst;

 err_end:
	kst_free(kst);
	return NULL;
}

#ifdef KT_SECURITY_FEATURE
__hidden char *kst_sep_filename_get(char *keyfile)
{
	if(strcmp(keyfile, KTKST_KEY_FILE) == 0 ) {
		return KTKST_KEY2_FILE;
	} else if(strcmp(keyfile, KTKST_KEY_FILE2) == 0 ) {
		return KTKST_KEY2_FILE2;
	}

	return NULL;
}

__hidden int kst_data_merge( unsigned char *data, int dsize, unsigned char *buf, int blen, unsigned char *buf2, int b2len)
{
	int i;

	if(data == NULL || dsize <= 0 ) {
		return -1;
	}

	if(buf == NULL || blen <= 0 ) {
		return -1;
	}

	if(buf2 == NULL || b2len <= 0 ) {
		return -1;
	}

	if(dsize != blen || dsize != b2len ) {
		return -1;
	}

	for(i=0; i<dsize; i++) {
		if(i%2 == 0) {
			data[i] = buf[i];
		} else {
			data[i] = buf2[i];
		}
	}

	return 0;
}

__hidden int kst_data_separate( unsigned char *data, int dsize, unsigned char *buf, int blen, unsigned char *buf2, int b2len)
{
	int i;

	if(data == NULL || dsize <= 0 ) {
		return -1;
	}

	if(buf == NULL || blen <= 0 ) {
		return -1;
	}

	if(buf2 == NULL || b2len <= 0 ) {
		return -1;
	}

	if(dsize != blen || dsize != b2len ) {
		return -1;
	}

	for(i=0; i<dsize; i++) {
		if(i%2 == 0) {
			buf[i] = data[i];
		} else {
			buf2[i] = data[i];
		}
	}

	return 0;
}
#endif

__hidden struct kst_t *kst_r_init(char *fname, unsigned char *hash_str, int hash_str_len)
{
	struct kst_t *kst = NULL;
#if (KT_SECURITY_FEATURE == 1)
	unsigned char buf[KST_TOTAL_SIZE];
	unsigned char buf2[KST_TOTAL_SIZE];
	int len, len2;
	char *sep_file = NULL;
#endif

	if (hash_str_len > MAX_HASH_STR)
		hash_str_len = MAX_HASH_STR;
	memcpy(_hash_str, hash_str, hash_str_len);
	_hash_str_len = hash_str_len;

	kst = kst_alloc(fname);
	if (!kst)
		return NULL;

#if (KT_SECURITY_FEATURE == 1)
	memset(buf, 0x00, KST_TOTAL_SIZE);
	memset(buf2, 0x00, KST_TOTAL_SIZE);
	// fill file
	if ((len=z_file_read(kst->fname, buf, KST_TOTAL_SIZE)) != KST_TOTAL_SIZE) {
		goto err_out;
	}
	sep_file = kst_sep_filename_get(kst->fname);
	if( sep_file ) {
		if ( (len2=z_file_read(sep_file, buf2, KST_TOTAL_SIZE)) != KST_TOTAL_SIZE) {
			goto err_out;
		}
	}

	if( kst_data_merge( kst->data, kst->data_sz, buf, len, buf2, len2) != 0 ) {
		goto err_out;
	}
#else
	// fill file
	if (z_file_read(kst->fname, kst->data, kst->data_sz) != kst->data_sz) {
		goto err_out;
	}
#endif

	// hash validate
	if (!kst_hash_validate(kst)) {
		goto err_out;
	}
	// all passed
	kst->f_exist = 1;
	return kst;

 err_out:
	kst_free(kst);

	return NULL;
}

__hidden int kst_get(struct kst_t *kst, int idx, unsigned char *data, int data_sz)
{
	int pos;
	int i;

	if (!kst || !kst->f_exist)
		return -1;	// error

	if (idx >= KST_INDEX_MAX)
		return -2;

	if (data_sz > 128)
		data_sz = 128;

	pos = index_get(&kst->data[KST_INDEX_OFFSET], idx, kst->data_sz);
	for (i = 0; i < data_sz; i++) {
		if (!kst_index_is_eol(pos)) {
			data[i] = kst->data[pos];
			pos = index_get(&kst->data[pos + 1], 0, kst->data_sz);
		} else {
			// eol reached.
			break;
		}
	}

	return i;
}

__hidden int kst_w_update(struct kst_t *kst, int idx, unsigned char *data, int data_len)
{
	int i, pos, last_pos;

	if (!kst || !kst->data || !kst->rseq_data || !data_len)
		return -1;

	last_pos = -1;

	for (i = 0; i < data_len; i++) {
		pos = rseq_get(&kst->rseq);
		if (pos < 0) {
			// unlink current index
			index_set(&kst->data[KST_INDEX_OFFSET], idx, kst_index_eol(), kst->data_sz);
			return -2;
		}
		// link with prev byte
		if (last_pos == -1)
			index_set(&kst->data[KST_INDEX_OFFSET], idx, pos, kst->data_sz);	// mark index area
		else
			index_set(&kst->data[last_pos + 1], 0, pos, kst->data_sz);

		kst->data[pos] = data[i];
		last_pos = pos;
	}
	index_set(&kst->data[last_pos + 1], 0, kst_index_eol(), kst->data_sz);

	return data_len;
}

__hidden int kst_w_final(struct kst_t *kst)
{
#if (KT_SECURITY_FEATURE == 1)
	unsigned char buf[KST_TOTAL_SIZE];
	unsigned char buf2[KST_TOTAL_SIZE];
	char *sep_file = NULL;
#endif

	kst_hash_generate(kst);
#if (KT_SECURITY_FEATURE == 1)
	kst_rand_str_get(buf, KST_ARENA_SIZE);
	kst_rand_str_get(buf2, KST_ARENA_SIZE);
	kst_data_separate( kst->data, kst->data_sz, buf, KST_TOTAL_SIZE, buf2, KST_TOTAL_SIZE);

	z_file_write(kst->fname, buf, KST_TOTAL_SIZE);

	sep_file = kst_sep_filename_get(kst->fname);
	if( sep_file ) {
		z_file_write(sep_file, buf2, KST_TOTAL_SIZE);
	}
#else
	z_file_write(kst->fname, kst->data, kst->data_sz);

	{ /* for test */
		unsigned char buf2[KST_TOTAL_SIZE];
		char *sep_file = NULL;
		sep_file = kst_sep_filename_get(kst->fname);
		if( sep_file ) {
			kst_rand_str_get(buf2, KST_ARENA_SIZE);
			z_file_write(sep_file, buf2, KST_TOTAL_SIZE);
		}
	}
#endif
	kst->f_exist = 1;
	return 0;
}

__hidden struct kst_t *kst_w_init(char *fname, unsigned char *hash_str, int hash_str_len)
{
	struct kst_t *kst = NULL;
	int i;

	if (hash_str_len > MAX_HASH_STR)
		hash_str_len = MAX_HASH_STR;
	memcpy(_hash_str, hash_str, hash_str_len);
	_hash_str_len = hash_str_len;

	kst = kst_alloc(fname);
	if (!kst)
		return NULL;

	i = KST_ARENA_SIZE / (1 + sizeof(index_type));	// ARENA : allocate n bytes at once
	//printf("Total %d bytes can be saved\n", i);

	kst->rseq_data = (index_type *) malloc(i * sizeof(index_type));
	if (!kst->rseq_data)
		goto err_out;

	kst->rseq_data_num = i;

	// init rand seq data
	for (i = 0; i < kst->rseq_data_num; i++)
		kst->rseq_data[i] = KST_ARENA_OFFSET + i * (1 + sizeof(index_type));

	rseq_init(&kst->rseq, kst->rseq_data, kst->rseq_data_num);

	// clear ARENA data
	kst_rand_str_get(&kst->data[KST_ARENA_OFFSET], KST_ARENA_SIZE);

	// clear INDEX area
	for (i = 0; i < KST_INDEX_MAX; i++) {
		index_set(&kst->data[KST_INDEX_OFFSET], i, kst_index_eol(), kst->data_sz);
	}

	kst_w_update(kst, KST_INDEX_MAX - 1, (unsigned char *)KST_MAGIC_MARK, KST_MAGIC_MARK_LEN);

	return kst;

 err_out:
	kst_free(kst);
	return NULL;
}

__hidden void kst_deinit(struct kst_t *kst)
{
	kst_free(kst);
}
