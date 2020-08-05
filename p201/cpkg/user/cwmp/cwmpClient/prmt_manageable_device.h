#ifndef __PRMT_MANAGEABLE_DEVICE_H__
#define __PRMT_MANAGEABLE_DEVICE_H__

#include "parameter_api.h"

#ifdef __cplusplus
extern "C" {
#endif 

#ifndef __PRMT_MANAGEABLE_DEVICE_C__
#undef  EXPORT_FUNCTION
#define EXPORT_FUNCTION extern
#else
#undef  EXPORT_FUNCTION
#define EXPORT_FUNCTION
#endif

EXPORT_FUNCTION struct sCWMP_ENTITY tManageableDevice[];

EXPORT_FUNCTION int get_ManageableDevice(char *name, struct sCWMP_ENTITY *entity, int *type, void **data);

#ifdef __cplusplus
}
#endif

#endif /* _PRMT_MANAGEABLE_DEVICE_H__ */

