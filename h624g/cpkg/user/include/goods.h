#ifndef _goods_h_
#define _goods_h_

#define GOODS_ID_VERSION 1

enum {
	S_OTHER = 0,
	S_SK,
	S_LG,
	S_KT
};

enum {
	T_2G = 0,
	T_DUAL_N,
	T_DUAL_AC
};

#define MK_GOODS_ID(v, t, s)	(((v) << 6) | ((t) << 2) | (s))

#if defined(__CONFIG_H624G__) || defined(__CONFIG_H624GMP__) || \
    defined(__CONFIG_GNT2100__) || \
    defined(__CONFIG_H724G__)
#define GOODS_ID	MK_GOODS_ID(GOODS_ID_VERSION, T_DUAL_AC, S_SK)
#else
#error GOODS_ID must be declared per profile!
#endif
#endif
