#ifndef __PRMT_WLANCONF_H__
#define __PRMT_WLANCONF_H__

#include "parameter_api.h"

#ifdef __cplusplus
extern "C" {
#endif 

#ifndef __PRMT_WLANCONF_C__
#undef  EXPORT_FUNCTION
#define EXPORT_FUNCTION extern
#else
#undef  EXPORT_FUNCTION
#define EXPORT_FUNCTION
#endif

EXPORT_FUNCTION struct sCWMP_ENTITY tWLANConf[];
EXPORT_FUNCTION struct sCWMP_ENTITY tWLANMAP[];
EXPORT_FUNCTION struct sCWMP_ENTITY tFWinodw[];

EXPORT_FUNCTION int WLANConfObj(char *name, struct sCWMP_ENTITY *entity, int type, void *data);
EXPORT_FUNCTION int get_WLANConf(char *name, struct sCWMP_ENTITY *entity, int *type, void **data);
EXPORT_FUNCTION int set_WLANConf(char *name, struct sCWMP_ENTITY *entity, int type, void *data);

EXPORT_FUNCTION int get_fWindowConf(char *name, struct sCWMP_ENTITY *entity, int *type, void **data);
EXPORT_FUNCTION int set_fWindowConf(char *name, struct sCWMP_ENTITY *entity, int type, void *data);
#ifdef __cplusplus
}
#endif

#endif /* __PRMT_WLANCONF_H__ */

