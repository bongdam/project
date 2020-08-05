#ifndef __KST_H__
#define __KST_H__

#ifndef __hidden
#define __hidden __attribute__((visibility("hidden")))
#endif

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

//#define KST_2B_PTR

#if defined(KST_2B_PTR)
typedef unsigned short index_type;
#else
typedef unsigned char index_type;
#endif

/*
 * rseq(random sequence) data 
 *  - shuffle data area, and get one by one from the first
 */

struct rseq_t {
	int i;
	index_type *a;
	int n;
};

struct kst_t {
	char *fname;

	unsigned char *data;
	int data_sz;

	index_type *rseq_data;
	int rseq_data_num;
	struct rseq_t rseq;

	int f_exist;
};

/******************************************************
 * kst get sequence
 *
 * 1. kst_r_init()
 * 2.  kst_get() -- can be multiple
 * 2.1 kst_get() -- can be multiple
 * 3. kst_deinit()
 *
 * kst write sequence : write는 기존 저장 데이타가 모두 날아감.
 * 
 * 1. kst_w_init() <---- 기존 data 모두 날아감
 * 2.  kst_w_update() --- can be multiple
 * 2.1 kst_w_update() --- can be multiple
 * 3. kst_w_final() --- file에 적음
 * 4. kst_deinit()
 ******************************************************/

__hidden struct kst_t *kst_r_init(char *fname, unsigned char *hash, int hash_len);
__hidden int kst_get(struct kst_t *kst, int idx, unsigned char *data, int data_sz);
__hidden void kst_deinit(struct kst_t *kst);

__hidden struct kst_t *kst_w_init(char *fname, unsigned char *hash, int hash_len);
__hidden int kst_w_update(struct kst_t *kst, int idx, unsigned char *data, int data_len);
__hidden int kst_w_final(struct kst_t *kst);

__hidden void kst_rand_str_get(void *_p, int n);

#define KST_MAGIC_MARK     "abcdefghijklmnopqrstuvwxyz"
#define KST_MAGIC_MARK_LEN 4
#endif
