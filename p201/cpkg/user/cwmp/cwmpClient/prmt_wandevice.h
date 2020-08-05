#ifndef __PRMT_WANDEVICE_H__
#define __PRMT_WANDEVICE_H__

#include "parameter_api.h"

#ifdef __cplusplus
extern "C" {
#endif 

#ifndef __PRMT_WANDEVICE_C__
#undef  EXPORT_FUNCTION
#define EXPORT_FUNCTION extern
#else
#undef  EXPORT_FUNCTION
#define EXPORT_FUNCTION
#endif

EXPORT_FUNCTION struct sCWMP_ENTITY tWANDevice[];
EXPORT_FUNCTION struct sCWMP_ENTITY tWANCONTBL[];

EXPORT_FUNCTION int get_WANDevice(char *name, struct sCWMP_ENTITY *entity, int *type, void **data);

#ifdef __cplusplus
}
#endif

#endif /* _PRMT_WANDEVICE_H__ */

