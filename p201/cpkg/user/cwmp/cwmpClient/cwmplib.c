#ifndef __CWMPLIB_C__
#define __CWMPLIB_C__

#include <bcmnvram.h>
#include "parameter_api.h"
#include "bcm_cfg_api.h"

// return the index in the entry table, -1 if not found.
int getStrIndexOf(char *strs[], char *name) {
	int idx;

	for (idx = 0; strs[idx]; idx++) {
		if (nv_strcmp(strs[idx], name))
			continue;
		return idx;
	}
	return -1;
}


// return the index in the entry table, -1 if not found.
int getIndexOf(struct sCWMP_ENTITY *tblCwmp, char *name) {
	int idx;

	for (idx = 0; tblCwmp[idx].name[0]; idx++) {
		if (nv_strcmp(tblCwmp[idx].name, name))
			continue;
		return idx;
	}
	return -1;
}

#ifdef __DAVO__
typedef struct __cwmp_lib_cfg__
{
	int (*cfg_get)(int, void *, int );
	int (*cfg_set)(int, void *, int );
	int (*cfg_chain_total)(int);
	int (*cfg_chain_get)(int, int , void *, int );
	int (*cfg_chain_update)(int, int, void *, int );
	int (*cfg_chain_add)(int, unsigned char *, int );
	int (*cfg_chain_delete)(int, int);
} CWMP_LIB;

static CWMP_LIB cwmp_cb;

int cwmp_cfg_init(void)
{
#if 1
	cwmp_cb.cfg_get 			= bcm_cfg_get;
	cwmp_cb.cfg_set 			= bcm_cfg_set;
	cwmp_cb.cfg_chain_total 	= bcm_cfg_chain_total;
	cwmp_cb.cfg_chain_get 		= bcm_cfg_chain_get;
	cwmp_cb.cfg_chain_update 	= bcm_cfg_chain_update;
	cwmp_cb.cfg_chain_add 		= bcm_cfg_chain_add;
	cwmp_cb.cfg_chain_delete 	= bcm_cfg_chain_delete;
#else
#error __AXT__ not define..
#endif
	return 0;
}

int cwmp_cfg_get( int api, void *ptr, int ptr_size)
{
	int ret=0;

	if( cwmp_cb.cfg_get) {
		ret = cwmp_cb.cfg_get(api, ptr, ptr_size);
	}

	return ret;
}

int cwmp_cfg_set( int api, void *ptr, int ptr_size)
{
	int ret=0;

	if( cwmp_cb.cfg_set) {
		ret = cwmp_cb.cfg_set(api, ptr, ptr_size);
	}

	return ret;
}

int cwmp_cfg_chain_total( int api )
{
	int ret=0;

	if( cwmp_cb.cfg_chain_total) {
		ret = cwmp_cb.cfg_chain_total(api);
	}

	return ret;
}

int cwmp_cfg_chain_get(int api, int id, void *ptr, int ptr_size)
{
	int ret=0;

	if( cwmp_cb.cfg_chain_get) {
		ret = cwmp_cb.cfg_chain_get(api, id, ptr, ptr_size);
	}

	return ret;

	return 1;
}

int cwmp_cfg_chain_update(int api, int id, void *ptr, int ptr_size)
{
	int ret=0;

	if( cwmp_cb.cfg_chain_update) {
		ret = cwmp_cb.cfg_chain_update(api, id, ptr, ptr_size);
	}

	return ret;
}

int cwmp_cfg_chain_add( int api, unsigned char *ptr, int ptr_size )
{
	int ret=0;

	if( cwmp_cb.cfg_chain_add) {
		ret = cwmp_cb.cfg_chain_add(api, ptr, ptr_size);
	}

	return ret;
}

int cwmp_cfg_chain_delete( int api, int id )
{
	int ret=0;

	if( cwmp_cb.cfg_chain_delete) {
		ret = cwmp_cb.cfg_chain_delete(api, id);
	}

	return ret;
}
#endif /* __DAVO__ */

#endif /* __CWMPLIB_C__ */

