#ifndef __PRMT_WANCONNECTIONDEVICE_H__
#define __PRMT_WANCONNECTIONDEVICE_H__

#include "parameter_api.h"

#ifdef __cplusplus
extern "C" {
#endif 

#ifndef __PRMT_WANCONNECTIONDEVICE_C__
#undef  EXPORT_FUNCTION
#define EXPORT_FUNCTION extern
#else
#undef  EXPORT_FUNCTION
#define EXPORT_FUNCTION
#endif

EXPORT_FUNCTION struct sCWMP_ENTITY tWANConnectionDevice[];

EXPORT_FUNCTION int get_WANConnectionDevice(char *name, struct sCWMP_ENTITY *entity, int *type, void **data);

#ifdef __cplusplus
}
#endif

#endif /* __PRMT_WANCONNECTIONDEVICE_H__ */
