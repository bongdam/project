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

#ifdef CONFIG_OEM_CJHV
#define GOODS_ID	MK_GOODS_ID(GOODS_ID_VERSION, T_DUAL_N, S_OTHER)
#else
#error GOODS_ID must be declared per profile!
#endif
#endif
