#ifndef __PRMT_OBJSAMPLE_H__
#define __PRMT_OBJSAMPLE_H__

#include "parameter_api.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef __PRMT_OBJSAMPLE_C__
#undef  EXPORT_FUNCTION
#define EXPORT_FUNCTION extern
#else
#undef  EXPORT_FUNCTION
#define EXPORT_FUNCTION
#endif

EXPORT_FUNCTION struct sCWMP_ENTITY tObjSample[];

EXPORT_FUNCTION int ObjMethodSample(char *name, struct sCWMP_ENTITY *entity, int type, void *data);
EXPORT_FUNCTION int getOBJENTITY(char *name, struct sCWMP_ENTITY *entity, int *type, void **data);
EXPORT_FUNCTION int setOBJENTITY(char *name, struct sCWMP_ENTITY *entity, int type, void *data);

#ifdef __cplusplus
}
#endif

#endif /* __PRMT_OBJSAMPLE_H__ */

