#ifndef __PRMT_BRIDGE_H
#define __PRMT_BRIDGE_H

#include "parameter_api.h"

#ifdef __cplusplus
extern "C" {
#endif 

#ifndef __PRMT_BRIDGE_C__
#undef  EXPORT_FUNCTION
#define EXPORT_FUNCTION extern
#else
#undef  EXPORT_FUNCTION
#define EXPORT_FUNCTION
#endif

EXPORT_FUNCTION struct sCWMP_ENTITY tVLANTbl[];
EXPORT_FUNCTION struct sCWMP_ENTITY tVLANMAP[];
EXPORT_FUNCTION struct sCWMP_ENTITY tBridgeTbl[];
EXPORT_FUNCTION struct sCWMP_ENTITY tBRDGMAP[];

EXPORT_FUNCTION int BridgeObj(char *name, struct sCWMP_ENTITY *entity, int type, void *data);
EXPORT_FUNCTION int VLANObj(char *name, struct sCWMP_ENTITY *entity, int type, void *data);
EXPORT_FUNCTION int get_bridge(char *name, struct sCWMP_ENTITY *entity, int* type, void **data);
EXPORT_FUNCTION int set_bridge(char *name, struct sCWMP_ENTITY *entity, int type, void *data);
EXPORT_FUNCTION int get_vlan(char *name, struct sCWMP_ENTITY *entity, int* type, void **data);
EXPORT_FUNCTION int set_vlan(char *name, struct sCWMP_ENTITY *entity, int type, void *data);
#ifdef __cplusplus
}
#endif

#endif /* __PRMT_BRIDGE_H__ */
