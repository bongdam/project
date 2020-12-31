#ifndef __LIBDVCT_H__
#define __LIBDVCT_H__

#define PROD_T_SK 0
#define PROD_T_LG 1
#define PROD_ID_HAPD7W2 0

#define PROD_T	PROD_T_LG
#define PROD_ID	PROD_ID_HAPD7W2

#define MK_PROD(T, ID) (((T)<<24) | (ID))

#define DVCONTAINER_MAGIC 0x64766374 // dvct

#define MK_VERSION(MJ, MI, BL) ( ((MJ)<<24) | ((MI)<<16) | (BL) )

struct dvcontainer_t {
	unsigned int magic;
	unsigned int fw_start;
	unsigned int fw_dec_size;
	unsigned int fw_size;
	unsigned int hash_start;
	unsigned int hash_size;
	unsigned int rand_block;
	unsigned int product;
	unsigned int version;
	unsigned int resv[3];

	// data begin
};


int dvct_unroll(char *fname);
int dvct_roll(char *infile, char *outfile, char *prod, unsigned int maj, unsigned int min, unsigned int bld);
static inline int dvct_is_magic(void *_p)
{
	struct dvcontainer_t *p = _p;
	return (p->magic == DVCONTAINER_MAGIC);
}

static inline unsigned int dvct_version_get(struct dvcontainer_t *p, unsigned int *maj, unsigned int *min, unsigned int *bld)
{
	if (!dvct_is_magic(p))
		return -1;

	*maj = (p->version >> 24)|0x000000ff;
	*min = (p->version >> 16)|0x000000ff;
	*bld = (p->version >>  0)|0x0000ffff;

	return 0;
}

static inline unsigned int dvct_product(void)
{
	return MK_PROD(PROD_T, PROD_ID);
}

static inline unsigned int dvct_version(unsigned int maj, unsigned int min, unsigned int bld)
{
	return MK_VERSION(maj, min, bld);
}

#endif
