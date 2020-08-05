#ifndef __PRMT_PORTMAPPING_H__
#define __PRMT_PORTMAPPING_H__

#include "parameter_api.h"

#ifdef __cplusplus
extern "C" {
#endif 

#ifndef __PRMT_PORTMAPPING_C__
#undef  EXPORT_FUNCTION
#define EXPORT_FUNCTION extern
#else
#undef  EXPORT_FUNCTION
#define EXPORT_FUNCTION
#endif

EXPORT_FUNCTION struct sCWMP_ENTITY tPortMapping[];
EXPORT_FUNCTION struct sCWMP_ENTITY tPortMapping[];

EXPORT_FUNCTION int get_PortMapping(char *name, struct sCWMP_ENTITY *entity, int *type, void **data);
EXPORT_FUNCTION int PortMapObj(char *name, struct sCWMP_ENTITY *entity, int type, void *data); 
EXPORT_FUNCTION int set_PortMapping(char *name, struct sCWMP_ENTITY *entity, int type, void *data);

#ifdef __cplusplus
}
#endif

#endif /* __PRMT_PORTMAPPING_H__ */

