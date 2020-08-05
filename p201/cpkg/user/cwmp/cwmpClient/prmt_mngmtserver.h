#ifndef __PRMT_MNGMTSERVER_H__
#define __PRMT_MNGMTSERVER_H__

#include "parameter_api.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef __PRMT_MNGMTSERVER_C__
#undef 	EXPORT_FUNCTION
#define EXPORT_FUNCTION extern
#else
#undef 	EXPORT_FUNCTION
#define EXPORT_FUNCTION
#endif

EXPORT_FUNCTION struct sCWMP_ENTITY tManagementServer[];

EXPORT_FUNCTION int getMngmntServer(char *name, struct sCWMP_ENTITY *entity, int *type, void **data);
EXPORT_FUNCTION int setMngmntServer(char *name, struct sCWMP_ENTITY *entity, int type, void *data );

#ifdef __cplusplus
}
#endif

#endif /* __PRMT_MNGMTSERVER_H__ */

