#ifndef __PRMT_ASSOCIATEDDEVICE_H__
#define __PRMT_ASSOCIATEDDEVICE_H__

#include "parameter_api.h"

#ifdef __cplusplus
extern "C" {
#endif 

#ifndef __PRMT_ASSOCIATEDDEVICE_C__
#undef  EXPORT_FUNCTION
#define EXPORT_FUNCTION extern
#else
#undef  EXPORT_FUNCTION
#define EXPORT_FUNCTION
#endif

EXPORT_FUNCTION struct sCWMP_ENTITY tAssociatedDevice[];
EXPORT_FUNCTION struct sCWMP_ENTITY tAssocObj[];

EXPORT_FUNCTION int get_AssociatedDevice(char *name, struct sCWMP_ENTITY *entity, int *type, void **data);
EXPORT_FUNCTION int AssocObj(char *name, struct sCWMP_ENTITY *entity, int type, void *data);

#ifdef __cplusplus
}
#endif

#endif /* __PRMT_ASSOCIATEDDEVICE_H__ */
