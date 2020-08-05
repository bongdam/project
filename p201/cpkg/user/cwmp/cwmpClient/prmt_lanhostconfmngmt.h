#ifndef __PRMT_LANHOSTCONFMNGMT_H__
#define __PRMT_LANHOSTCONFMNGMT_H__

#include "parameter_api.h"

#ifdef __cplusplus
extern "C" {
#endif 

#ifndef __PRMT_LANHOSTCONFMNGMT_C__
#undef  EXPORT_FUNCTION
#define EXPORT_FUNCTION extern
#else
#undef  EXPORT_FUNCTION
#define EXPORT_FUNCTION
#endif

EXPORT_FUNCTION struct sCWMP_ENTITY tLanHostConfMngmt[];

EXPORT_FUNCTION int get_LanHostConfMngmt(char *name, struct sCWMP_ENTITY *entity, int *type, void **data);
EXPORT_FUNCTION int set_LanHostConfMngmt(char *name, struct sCWMP_ENTITY *entity, int type, void *data);

#ifdef __cplusplus
}
#endif

#endif /* _PRMT_LANHOSTCONFMNGMT_H__ */

