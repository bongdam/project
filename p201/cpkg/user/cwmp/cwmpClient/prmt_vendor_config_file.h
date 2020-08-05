#ifndef __PRMT_VENDOR_CONFIG_FILE_H__
#define __PRMT_VENDOR_CONFIG_FILE_H__

#include "parameter_api.h"

#ifdef __cplusplus
extern "C" {
#endif 

#ifndef __PRMT_VENDOR_CONFIG_FILE_C__
#undef  EXPORT_FUNCTION
#define EXPORT_FUNCTION extern
#else
#undef  EXPORT_FUNCTION
#define EXPORT_FUNCTION
#endif

EXPORT_FUNCTION struct sCWMP_ENTITY tVendorConfigFile[];
EXPORT_FUNCTION struct sCWMP_ENTITY tVendorConfigMap[];

EXPORT_FUNCTION int get_VendorConfigFile(char *name, struct sCWMP_ENTITY *entity, int *type, void **data);

#ifdef __cplusplus
}
#endif

#endif /* _PRMT_VENDOR_CONFIG_FILE_H__ */

