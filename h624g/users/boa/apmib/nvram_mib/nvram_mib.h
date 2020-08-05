#ifndef _NVRAM_MIB_H_
#define _NVRAM_MIB_H_

#include <stdarg.h>

/* name upto 40 + value TX_POWER_5G... 192 * 2 */
#define APMIB_NVRAM_MAX_VALUE_LEN	512

#ifndef TRUE
#define TRUE 1
#define FALSE 0
#endif

typedef int BOOL;

#define HW_SECT		(1 << 0)
#define WLAN_SECT	(1 << 1)

struct mib {
	int id;
	const char *name;
	int type;
	unsigned short size;
	unsigned short section;
};

struct mib_tbl_operation {
	int _type;
	int (*_get)(void *, const char *, const struct mib *);
	int (*_add)(void *, const struct mib *, const struct mib *);
	int (*_del)(void *, const struct mib *, const struct mib *);
};

struct mib_iterator {
	void *priv_data;
	char * (*_fetch)(void *, int);
	int (*_match)(const char *, void *);
};

const struct mib *ysearch_mib_struct(int id);
const struct mib *ymib_first(void);
const struct mib *ymib_next(const struct mib *p);

const struct mib_tbl_operation *ysearch_mib_top(int type);

char *ystrncpy(char *dest, const char *src, size_t n);
char *yitoxa(char *dst, unsigned char *val, int valsize);
int yxatoi(unsigned char *dst, const char *src, int len);
char *yunescape(char *str);

char *ynvram_name(char *buf, size_t len, const char *wroot, unsigned int section);
int ynvram_putarray(const char *name, unsigned char *pbyte, unsigned short len);

char *ynvram_get(const char *arg, ...);
BOOL ynvram_put(const char *arg, ...);
#define ynvram_unset	ynvram_put

typedef enum {
	HW_DFL = 0,
	RUN_DFL,
	REV_DFL
} DFL_TYPE_T;

const char *apmib_file_dfl(DFL_TYPE_T);

int apmib_get_tblarray(int id, void *value, const struct mib *mib);
int apmib_add_tblarray(int id, void *value, const struct mib *mib, int num_id);
int apmib_del_tblarray(int id, void *value, const struct mib *mib, int num_id, int flush);
int apmib_mod_tblentry(void);

char **apmib_iterate(struct mib_iterator *it);

extern int wlan_idx, vwlan_idx, wlan_idx_bak, vwlan_idx_bak;
extern const size_t _mib_max_unitsiz;

#define L_CRIT  -2	/* 31 RED */
#define L_ERR   -1	/* 35 MAGENTA */
#define L_WARN   1	/* 33 YELLOW */
#define L_INFO   2	/* 34 BLUE */
#define L_DBG    3

#ifndef _NDEBUG
int yprintf(int level, const char *fmt, ...);
#define _DEBUG(level, fmt, args...)	yprintf(level, "%s(%d) " fmt, __func__ , __LINE__, ## args)
#define _PDEBUG(fmt, args...)	yprintf(L_DBG, fmt, ## args)
#else
#define _DEBUG(level, arg...)	do {} while (0)
#define _PDEBUG(fmt, args...)	do {} while (0)
#endif

extern int nm_errno;

enum {
	ENM_NOSYS = 1,	/* Function not implemented */
	ENM_INVAL,	/* Invalid argument */
	ENM_IDENTICAL,	/* Identical value */
	ENM_MEMORY,	/* Out of memory */
	ENM_NOMIB,	/* Mib entry not found in table */
	ENM_BADFMT,	/* Bad format */
	ENM_BADTYPE,	/* Type not supported */
	ENM_OORNG,	/* Out of range */
	ENM_FULL,	/* Entry is full */
};

int apmib_set_hist_put(int id);
int apmib_set_hist_string_put(const char *name);
int apmib_set_hist_get(void);
void apmib_set_hist_clear(void);
int apmib_set_hist_peek(void);
int apmib_set_hist_peek_last(void);
int apmib_set_hist_search(int id);
int apmib_set_hist_search_any(int id, ...);
int apmib_set_hist_strstr(char *name);
char *apmib_strerror(int errnum);
int apmib_set_hist_real_id(int id);
int apmib_set_hist_is_string(int id);

#endif	/* _NVRAM_MIB_H_ */
