//------------------------------------------------------------------------------
//  davo snmp trap header file
//------------------------------------------------------------------------------
#ifndef     _SNMP_RESP_H__
#define     _SNMP_RESP_H__

#if defined(__cplusplus)
extern "C" {
#endif

#include "./engine/agt_engine.h"

extern unsigned char *build_snmp_response_without_list_of_varbind(raw_snmp_info_t *pi);
extern int correct_snmp_response_with_lengths(raw_snmp_info_t *pi, long error_status, long error_index);

/*
**  Function Prototype
*/

int snmp_send_response(raw_snmp_info_t *pMsg, int socket);
unsigned char *make_resp_v2c_headr(raw_snmp_info_t *pMsg, int *p_out_length);
unsigned char *make_resp_tail(raw_snmp_info_t *pMsg, char *out_data, int *out_length);


#if defined(__cplusplus)
}
#endif

#endif  //#ifndef     _SNMP_RESP_H__

