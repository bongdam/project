#ifndef __BCM_CFG_API_H__
#define __BCM_CFG_API_H__

#ifndef __BCM_CFG_API_C__
#undef 	EXPORT_FUNCTION
#define EXPORT_FUNCTION extern
#else
#undef 	EXPORT_FUNCTION
#define EXPORT_FUNCTION
#endif

typedef struct __obj_sample__  
{
	int InstanceNum;
	int param;
	struct __obj_sample__ *next;
} OBJ_SAMPLE_T;

EXPORT_FUNCTION int bcm_cfg_get( int api, void *ptr, int ptr_size);
EXPORT_FUNCTION int bcm_cfg_set( int api, void *ptr, int ptr_size);
EXPORT_FUNCTION int bcm_cfg_chain_total( int api );
EXPORT_FUNCTION int bcm_cfg_chain_get(int api, int id, void *ptr, int ptr_size);
EXPORT_FUNCTION int bcm_cfg_chain_update(int api, int id, void *ptr, int ptr_size );
EXPORT_FUNCTION int bcm_cfg_chain_add( int api, unsigned char *ptr, int ptr_size );
EXPORT_FUNCTION int bcm_cfg_chain_delete( int api, int id );

#endif /* __BCM_CFG_API_H__ */

