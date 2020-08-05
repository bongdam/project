#ifndef __CWMPCLIENTLIB_H__
#define __CWMPCLIENTLIB_H__

#ifndef __CWMPCLIENTLIB_C__
#undef 	EXPORT_FUNCTION
#define EXPORT_FUNCTION extern
#else
#undef 	EXPORT_FUNCTION
#define EXPORT_FUNCTION
#endif

EXPORT_FUNCTION int cwmp_free_userdata( struct cwmp_userdata *user );
EXPORT_FUNCTION void cwmp_SaveReboot( struct cwmp_userdata *user, int reboot_flag, int apply);	//APACRTL-483
#if 1
EXPORT_FUNCTION void cwmp_reset_DownloadInfo( DownloadInfo_T *dlinfo, int dlway );
#else
EXPORT_FUNCTION void cwmp_reset_download( struct cwmp__Download *dw );
#endif
EXPORT_FUNCTION void *cwmp_valuedup( struct soap *soap, int type, void *data );
EXPORT_FUNCTION int get_ParameterNameTotalCount( struct ArrayOfStrings *s );
EXPORT_FUNCTION int push_SetParameterVaulesFault( struct soap *soap, struct node **node, char *name, int code);
EXPORT_FUNCTION struct cwmp__SetParameterValuesFault *pop_SetParameterVaulesFault( struct soap *soap, struct node **node);
EXPORT_FUNCTION int cwmp_CreateInform( struct soap *soap, int *type, void **data, unsigned int e, char *opt);
EXPORT_FUNCTION int cwmp_CreateTransferComplete( struct soap *soap, int *type, void **data);
EXPORT_FUNCTION int cwmp_CreateAutonomousTransferComplete( struct soap *soap, int *type, void **data);
EXPORT_FUNCTION int cwmp_CreateGetRPCMethods( struct soap *soap, int *type, void **data);
EXPORT_FUNCTION int cwmp_InformResponse( struct soap *soap, struct cwmp__InformResponse *Resp, int *type, void **data);
EXPORT_FUNCTION int cwmp_TransferCompleteResponse( struct soap *soap, struct cwmp__TransferCompleteResponse *Resp, int *type, void **data);
EXPORT_FUNCTION int cwmp_GetRPCMethodsResponse( struct soap *soap, struct cwmp__GetRPCMethodsResponse *resp, int *type, void **data);
EXPORT_FUNCTION int cwmp_GetParameterValues( struct soap *soap, struct cwmp__GetParameterValues *req, int *type, void **data);
EXPORT_FUNCTION int cwmp_GetRPCMethods( struct soap *soap, struct cwmp__GetRPCMethods *req, int *type, void **data);
EXPORT_FUNCTION int cwmp_SetParameterValues( struct soap *soap, struct cwmp__SetParameterValues *req, int *type, void **data);
EXPORT_FUNCTION int cwmp_GetParameterNames( struct soap *soap, struct cwmp__GetParameterNames *req, int *type, void **data);
EXPORT_FUNCTION int cwmp_SetParameterAttributes( struct soap *soap, struct cwmp__SetParameterAttributes *req, int *type, void **data);
EXPORT_FUNCTION int cwmp_GetParameterAttributes( struct soap *soap, struct cwmp__GetParameterAttributes *req, int *type, void **data);
EXPORT_FUNCTION int cwmp_AddObject( struct soap *soap, struct cwmp__AddObject *req, int *type, void **data);
EXPORT_FUNCTION int cwmp_DeleteObject( struct soap *soap, struct cwmp__DeleteObject *req, int *type, void **data);
#if 1
EXPORT_FUNCTION int cwmp_Download( struct soap *soap, struct cwmp__Download *req, int *type, void **data);
#else
EXPORT_FUNCTION int cwmp_Download( struct soap *soap, struct cwmp__Download *req, int *type, void **data);
#endif
EXPORT_FUNCTION int cwmp_Reboot( struct soap *soap, struct cwmp__Reboot *req, int *type, void **data);
EXPORT_FUNCTION int cwmp_Upload( struct soap *soap, struct cwmp__Upload *req, int *type, void **data);
EXPORT_FUNCTION int cwmp_FactoryReset( struct soap *soap, struct cwmp__FactoryReset *req, int *type, void **data);
EXPORT_FUNCTION void cwmp_header_free( struct soap *soap );
EXPORT_FUNCTION int cwmp_header_init( struct soap *soap );
EXPORT_FUNCTION int cwmp_header_set_NoMoreRequests( struct soap *soap, int flag );
EXPORT_FUNCTION int cwmp_header_set_HoldRequests( struct soap *soap, int flag );
EXPORT_FUNCTION int cwmp_header_handle_request( struct soap *soap );
EXPORT_FUNCTION int cwmp_header_handle_response( struct soap *soap );
EXPORT_FUNCTION int cwmp_set_fault( struct soap	*soap, int 		cwmp_faultcode, char 		*cwmp_faultstring);
EXPORT_FUNCTION int cwmp_set_SetParameterValuesFault( struct soap *soap, struct node **root);
EXPORT_FUNCTION int cwmp_handle_fault( struct soap *soap, struct SOAP_ENV__Fault *fault, int *type, void **data);
EXPORT_FUNCTION int cwmp_handle_unknown( struct soap *soap, void *req, int *type, void **data);
EXPORT_FUNCTION void cwmp_setup_credential(struct cpe_machine *m);
EXPORT_FUNCTION int cwmp_process_send( struct soap *soap, const char *soap_endpoint, const char *soap_action, const int type, const void *data);
EXPORT_FUNCTION int cwmp_process_recv(struct soap *soap, int *type, void **data);
EXPORT_FUNCTION int MgmtSrvGetConReqURL(char *url, unsigned int size);
EXPORT_FUNCTION int cwmpMgmtGetPeriodicInformInterval(void);
EXPORT_FUNCTION void cwmpMgmtSetPeriodicInformInterval(int val);
EXPORT_FUNCTION void cwmpMgmtSrvInformInterval();
EXPORT_FUNCTION void cwmpMgmtSetHPPeriod(int period);
EXPORT_FUNCTION void cwmpMgmtSetHPttl(int ttl);
EXPORT_FUNCTION void cwmpSetReboot(void);
EXPORT_FUNCTION void handle_io(int sig);
EXPORT_FUNCTION void cwmpMsgInit();
EXPORT_FUNCTION int ACSEventType (struct cpe_machine *m);
EXPORT_FUNCTION int cwmp_process(struct soap *soap, const char *soap_endpoint, const char *soap_action);
EXPORT_FUNCTION int check_wan_ip_changed(int write_changed);    //APACRTL-337

#endif /* __CWMPCLIENT_H__ */

