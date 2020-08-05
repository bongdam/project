#ifndef __PRMT_WLAN_H__
#define __PRMT_WLAN_H__

#include "parameter_api.h"

#ifdef __cplusplus
extern "C" {
#endif 

#ifndef __PRMT_WLAN_C__
#undef  EXPORT_FUNCTION
#define EXPORT_FUNCTION extern
#else
#undef  EXPORT_FUNCTION
#define EXPORT_FUNCTION
#endif

EXPORT_FUNCTION struct sCWMP_ENTITY tWLAN[];
EXPORT_FUNCTION struct sCWMP_ENTITY tWLANMONMAP[];

EXPORT_FUNCTION int WLANMonObj(char *name, struct sCWMP_ENTITY *entity, int type, void *data);
EXPORT_FUNCTION int get_WLAN(char *name, struct sCWMP_ENTITY *entity, int *type, void **data);
EXPORT_FUNCTION int set_WLAN(char *name, struct sCWMP_ENTITY *entity, int type, void *data);

#ifdef __cplusplus
}
#endif

#endif /* __PRMT_WLAN_H__ */

