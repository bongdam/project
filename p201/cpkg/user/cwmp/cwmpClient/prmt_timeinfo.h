#ifndef __PRMT_TIMEINFO_H__
#define __PRMT_TIMEINFO_H__

#include "parameter_api.h"

#ifdef __cplusplus
extern "C" {
#endif 

#ifndef __PRMT_TIMEINFO_C__
#undef  EXPORT_FUNCTION
#define EXPORT_FUNCTION extern
#else
#undef  EXPORT_FUNCTION
#define EXPORT_FUNCTION
#endif

EXPORT_FUNCTION struct sCWMP_ENTITY tTimeInfo[];

EXPORT_FUNCTION int get_TimeInfo(char *name, struct sCWMP_ENTITY *entity, int *type, void **data);
EXPORT_FUNCTION int set_TimeInfo(char *name, struct sCWMP_ENTITY *entity, int type, void *data);

#ifdef __cplusplus
}
#endif

#endif /* _PRMT_TIMEINFO_H__ */

