#ifndef __PRMT_HOST_H__
#define __PRMT_HOST_H__

#include "parameter_api.h"

#ifdef __cplusplus
extern "C" {
#endif 

#ifndef __PRMT_HOST_C__
#undef  EXPORT_FUNCTION
#define EXPORT_FUNCTION extern
#else
#undef  EXPORT_FUNCTION
#define EXPORT_FUNCTION
#endif

EXPORT_FUNCTION struct sCWMP_ENTITY tHost[];
EXPORT_FUNCTION struct sCWMP_ENTITY tHostMAP[];

EXPORT_FUNCTION int get_Host(char *name, struct sCWMP_ENTITY *entity, int *type, void **data);
EXPORT_FUNCTION int HostObj(char *name, struct sCWMP_ENTITY *entity, int type, void *data);

#ifdef __cplusplus
}
#endif

#endif /* __PRMT_HOST_H__ */

