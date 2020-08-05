#ifndef _goods_h_
#define _goods_h_

/* 0 ~ 7 vendor */
enum {
	S_OTHER,
	S_SK,
	S_LG,
	S_KT,
	S_CJHV,
	S_LGHV,
	S_SEIKO
};

/* 0 ~ 7 wifi form factor */
enum {
	T_2G = 0,
	T_DUAL_N,
	T_DUAL_AC,
	T_TUAL_AX,
};

enum {
	ODM = 1,
};

#define MK_GOODS_ID(v, t, s)	(((v) << 6) | ((t) << 3) | (s))
#define GOODS_ID MK_GOODS_ID(DEV_PRODUCT_ID, DEV_WIFI_FFACTOR, DEV_VENDOR_ID)
#endif
