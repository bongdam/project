//////gsoapopt t
//gsoap cwmp service name:	cwmp
//gsoap cwmp service style:	rpc
//gsoap cwmp service encoding:	encoded
//gsoap cwmp schema namespace:	urn:dslforum-org:cwmp-1-0

#ifndef false
#define false 0
#endif
#ifndef true
#define true  1
#endif

typedef enum mybool {_0=0, _1=1, _true=1, _false=0} xsd__boolean;

typedef int cwmp__None;
typedef int cwmp__Empty;
typedef int cwmp__EmptyResponse;
typedef int cwmp__UnKnown;
typedef int cwmp__UnKnownResponse;

/*for dreytek acs, string array's type == cwmp:string[], not xsd:string[]*/
typedef char*  cwmp__string;


struct xsd__base64
{
	unsigned int	*__ptr;
	int		__size;
};
/*******************************************************************/
/*  header & cwmp's fault structure */
/*******************************************************************/
struct cwmp__SetParameterValuesFault
{
	char		*ParameterName;
	unsigned int	FaultCode;
	char		*FaultString;
};
struct cwmp__Fault
{
	unsigned int				FaultCode;
	char					*FaultString;
	int					__sizeSPVF;
	struct cwmp__SetParameterValuesFault	*SetParameterValuesFault;
};
struct SOAP_ENV__Detail
{
	struct cwmp__Fault	*cwmp__Fault;
	char 			*__any;
};
struct SOAP_ENV__Header
{
mustUnderstand	char		*cwmp__ID;
mustUnderstand	xsd__boolean	*cwmp__HoldRequests;
		xsd__boolean	*cwmp__NoMoreRequests;
};
/*******************************************************************/
/*  common structure */
/*******************************************************************/
struct cwmp__ParameterValueStruct
{
	char	*Name;
	int	__type;
	void	*Value;
};
struct ParameterValueList
{
	struct cwmp__ParameterValueStruct	*__ptrParameterValueStruct;
	int					__size;
};
struct ArrayOfStrings
{
	/*for dreytek acs, string array's type == cwmp:string[], not xsd:string[]*/
	//cwmp__string *__ptrstring; //use <string>xxxxx</string> ????
	char	**__ptrstring; //use <string>xxxxx</string> ????
	int	__size;
};
/*******************************************************************/
/*  GetRPCMethods structure */
/*******************************************************************/
struct cwmp__GetRPCMethodsResponse
{
	struct ArrayOfStrings	MethodList;
};
/*******************************************************************/
/*  Inform structure */
/*******************************************************************/
struct cwmp__DeviceldStruct
{
	char	*Manufacturer;
	char	*OUI;
	char	*ProductClass;
	char	*SerialNumber;
};
struct cwmp__EventStruct
{
	char	*EventCode;
	char	*CommandKey;
};
struct Event
{
	struct cwmp__EventStruct	*__ptrEventStruct;
	int				__size;
};
/*******************************************************************/
/*  InformResponse structure */
/*******************************************************************/
struct cwmp__InformResponse
{
	unsigned int	MaxEnvelopes;
};
/*******************************************************************/
/*  TransferComplete structure */
/*******************************************************************/
struct cwmp__FaultStruct
{
	unsigned int	FaultCode;
	char		*FaultString;
};
struct cwmp__TransferCompleteResponse
{
	void		*a;
};
/*******************************************************************/
/*  SetParameterValues structure */
/*******************************************************************/
struct cwmp__SetParameterValuesResponse
{
	int	Status;
};
/*******************************************************************/
/*  GetParameterValues structure */
/*******************************************************************/
struct cwmp__GetParameterValuesResponse
{
	struct ParameterValueList	ParameterList;
};
/*******************************************************************/
/*  GetParameterNames structure */
/*******************************************************************/
struct cwmp__ParameterInfoStruct
{
	char		*Name;
	xsd__boolean	Writable;
};
struct ParameterNameList
{
	struct cwmp__ParameterInfoStruct	*__ptrParameterInfoStruct;
	int					__size;
};
struct cwmp__GetParameterNamesResponse
{
	struct ParameterNameList	ParameterList;
};
/*******************************************************************/
/*  SetParameterAttributes structure */
/*******************************************************************/
struct cwmp__SetParameterAttributesStruct
{
	char			*Name;
	xsd__boolean		NotificationChange;
	int			Notification;
	xsd__boolean		AccessListChange;
	struct ArrayOfStrings	AccessList;
};
struct ParameterAttributesList
{
	struct cwmp__SetParameterAttributesStruct	*__ptrSetParameterAttributesStruct;
	int						__size;
};
struct cwmp__SetParameterAttributesResponse
{
	void	*a;
};
/*******************************************************************/
/*  GetParameterAttributes structure */
/*******************************************************************/
struct cwmp__ParameterAttributeStruct
{
	char			*Name;
	int			Notification;
	struct ArrayOfStrings	AccessList;
};
struct ParameterAttributesStructList
{
	struct cwmp__ParameterAttributeStruct	*__ptrParameterAttributeStruct;
	int					__size;
};
struct cwmp__GetParameterAttributesResponse
{
	struct ParameterAttributesStructList	ParameterList;
};
/*******************************************************************/
/*  AddObject structure */
/*******************************************************************/
struct cwmp__AddObjectResponse
{
	unsigned int	InstanceNumber;
	int		Status;
};
/*******************************************************************/
/*  DeleteObject structure */
/*******************************************************************/
struct cwmp__DeleteObjectResponse
{
	int		Status;
};
/*******************************************************************/
/*  DownloadResponse structure */
/*******************************************************************/
struct cwmp__DownloadResponse
{
	int		Status;
	time_t		StartTime;
	time_t		CompleteTime;
};
/*******************************************************************/
/*  RebootResponse structure */
/*******************************************************************/
struct cwmp__RebootResponse
{
	void	*a;
};
/*******************************************************************/
/*  UploadResponse structure */
/*******************************************************************/
struct cwmp__UploadResponse
{
	int		Status;
	time_t		StartTime;
	time_t		CompleteTime;
};
/*******************************************************************/
/*  FactoryResetResponse structure */
/*******************************************************************/
struct cwmp__FactoryResetResponse
{
	void	*a;
};
/*******************************************************************/
/*  RPC method definitions */
/*******************************************************************/
/* generic method */
int cwmp__GetRPCMethods(
	void					*Req,
	struct cwmp__GetRPCMethodsResponse	*Resp);

/* server method */
int cwmp__Inform(
	struct cwmp__DeviceldStruct	DeviceId,
	struct Event			Event,
	unsigned int			MaxEnvelopes,
	time_t				CurrentTime,
	unsigned int			RetryCount,
	struct ParameterValueList	ParameterList,
	struct cwmp__InformResponse	*Resp);

int cwmp__TransferComplete(
	char					*CommandKey,
	struct cwmp__FaultStruct		FaultStruct,
	time_t					StartTime,
	time_t					CompleteTime,
	struct cwmp__TransferCompleteResponse	*Resp);

/* client method */
int cwmp__SetParameterValues(
	struct ParameterValueList		ParameterList,
	char					*ParameterKey,
	struct cwmp__SetParameterValuesResponse	*Resp);

int cwmp__GetParameterValues(
	struct ArrayOfStrings			ParameterNames,
	struct cwmp__GetParameterValuesResponse	*Resp);

int cwmp__GetParameterNames(
	char					*ParameterPath,
	xsd__boolean				NextLevel,
	struct cwmp__GetParameterNamesResponse	*Resp);
	
int cwmp__SetParameterAttributes(
	struct ParameterAttributesList			ParameterList,
	struct cwmp__SetParameterAttributesResponse	*Resp);

int cwmp__GetParameterAttributes(
	struct ArrayOfStrings				ParameterNames,
	struct cwmp__GetParameterAttributesResponse	*Resp);

int cwmp__AddObject(
	char				*ObjectName,
	char				*ParameterKey,
	struct cwmp__AddObjectResponse	*Resp);
	
int cwmp__DeleteObject(
	char					*ObjectName,
	char					*ParameterKey,
	struct cwmp__DeleteObjectResponse	*Resp);
	
int cwmp__Download(
	char				*CommandKey,
	char				*FileType,
	char				*URL,
	char				*Username,
	char				*Password,
	unsigned int		FileSize,
	char				*TargetFileName,
	unsigned int		DelaySeconds,
	char				*SuccessURL,
	char				*FailureURL,
	struct cwmp__DownloadResponse	*Resp);
	
int cwmp__Reboot(
	char				*CommandKey,
	struct cwmp__RebootResponse	*Resp);

int cwmp__Upload(
	char				*CommandKey,
	char				*FileType,
	char				*URL,
	char				*Username,
	char				*Password,
	unsigned int			DelaySeconds,
	struct cwmp__UploadResponse	*Resp);

int cwmp__FactoryReset(
	void					*a,
	struct cwmp__FactoryResetResponse	*Resp);
