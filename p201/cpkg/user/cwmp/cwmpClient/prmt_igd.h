#ifndef __PRMT_IGD_H__
#define __PRMT_IGD_H__

#include "parameter_api.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef __PRMT_IGD_C__
#undef  EXPORT_FUNCTION
#define EXPORT_FUNCTION extern
#else
#undef  EXPORT_FUNCTION
#define EXPORT_FUNCTION
#endif


EXPORT_FUNCTION struct sCWMP_ENTITY tIGD[];
EXPORT_FUNCTION struct sCWMP_ENTITY tROOT[];

int get_DevSummary(char *name, struct sCWMP_ENTITY *entity, int* type, void **data);
int get_SendDiaglog(char *name, struct sCWMP_ENTITY *entity, int* type, void **data);
int set_SendDiaglog(char *name, struct sCWMP_ENTITY *entity, int type, void *data);

#ifdef __cplusplus
}
#endif

#endif /* __PRMT_IGD_H__ */

