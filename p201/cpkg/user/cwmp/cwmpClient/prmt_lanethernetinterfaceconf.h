#ifndef __PRMT_LANETHERNETINTERFACECONF_H__
#define __PRMT_LANETHERNETINTERFACECONF_H__

#include "parameter_api.h"

#ifdef __cplusplus
extern "C" {
#endif 

#ifndef __PRMT_LANETHERNETINTERFACECONF_C__
#undef  EXPORT_FUNCTION
#define EXPORT_FUNCTION extern
#else
#undef  EXPORT_FUNCTION
#define EXPORT_FUNCTION
#endif

EXPORT_FUNCTION struct sCWMP_ENTITY tLanEternetInterfaceConf[];
EXPORT_FUNCTION struct sCWMP_ENTITY tLANETHINFMAP[];

EXPORT_FUNCTION int LANETHINFObj(char *name, struct sCWMP_ENTITY *entity, int type, void *data);
EXPORT_FUNCTION int get_LanEternetInterfaceConf(char *name, struct sCWMP_ENTITY *entity, int *type, void **data);
EXPORT_FUNCTION int set_LanEternetInterfaceConf(char *name, struct sCWMP_ENTITY *entity, int type, void *data);

#ifdef __cplusplus
}
#endif

#endif /* _PRMT_LANETHERNETINTERFACECONF_H__ */

