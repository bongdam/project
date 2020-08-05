#ifndef __PRMT_DEVICEINFO_H__
#define __PRMT_DEVICEINFO_H__

#include "parameter_api.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef __PRMT_DEVICEINFO_C__
#undef  EXPORT_FUNCTION
#define EXPORT_FUNCTION extern
#else
#undef  EXPORT_FUNCTION
#define EXPORT_FUNCTION
#endif

EXPORT_FUNCTION struct sCWMP_ENTITY tDeviceInfo[];

EXPORT_FUNCTION int getDeviceInfo(char *name, struct sCWMP_ENTITY *entity, int *type, void **data);
EXPORT_FUNCTION int setDeviceInfo(char *name, struct sCWMP_ENTITY *entity, int type, void *data);

#ifdef __cplusplus
}
#endif

#endif /* _PRMT_DEVICEINFO_H__ */

