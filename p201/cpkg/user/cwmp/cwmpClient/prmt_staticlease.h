#include "parameter_api.h"

#ifndef __PRMT_STATICLEASE_C__
#undef  EXPORT_FUNCTION
#define EXPORT_FUNCTION extern
#else
#undef  EXPORT_FUNCTION
#define EXPORT_FUNCTION
#endif

EXPORT_FUNCTION struct sCWMP_ENTITY tStaticLeaseInfo[];
EXPORT_FUNCTION struct sCWMP_ENTITY tStaticLeaseMAP[];

EXPORT_FUNCTION int get_StaticLeaseConf(char *name, struct sCWMP_ENTITY *entity, int* type, void **data);
EXPORT_FUNCTION int set_StaticLeaseConf(char *name, struct sCWMP_ENTITY *entity, int type, void *data);
EXPORT_FUNCTION int StaticLeaseObj(char *name, struct sCWMP_ENTITY *entity, int type, void *data) ;
