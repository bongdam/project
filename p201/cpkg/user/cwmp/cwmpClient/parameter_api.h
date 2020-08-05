#ifndef __PARAMETER_API_H__
#define __PARAMETER_API_H__

#ifdef __cplusplus
extern "C" {
#endif

#ifndef __PARAMETER_API_C__
#undef  EXPORT_FUNCTION
#define EXPORT_FUNCTION extern
#else
#undef  EXPORT_FUNCTION
#define EXPORT_FUNCTION
#endif

#include "soapH.h"

#define MAX_PRMT_NAME_LEN	128 //256 is better

#define SHOWMEMSTATUS( fn, fl ) { \
char abuf[32]; \
int  st; \
fprintf( stdout, "<%s:%d>\n", fn, fl ); \
snprintf(abuf, sizeof(abuf), "cat  /proc/%d/status", getpid() ); \
system( abuf); \
wait( &st ); \
fflush(NULL); \
}

/***************************************************************************
 ***	debug macro
 ***    #define CWMPDBGZ(X)		fprintf X 
 ***    or
 ***    #define CWMPDBGZ(X)		while(0){}
 ***	ex: CWMPDBG( 1, ( stdout, "<%s:%d>\n", __FUNCTION__, __LINE__ ) );
 ***************************************************************************/
int gDebugFlag;
#define CWMPDBG0(X)		do{if(gDebugFlag&0x01) fprintf X; } while(0);	//info
#define CWMPDBG1(X)		do{if(gDebugFlag&0x02) fprintf X; } while(0);	// debug 1
#define CWMPDBG2(X)		do{if(gDebugFlag&0x04) fprintf X; } while(0);	// debug 2
#define CWMPDBG3(X)		do{if(gDebugFlag&0x08) fprintf X; } while(0);	// debug 3
#define CWMPDBG(level,X)	do{if(gDebugFlag&(1<<level)) fprintf X; } while(0);




/***********************************************************************/
/* Node utility functions. */
/***********************************************************************/
struct node{
	struct node	*next;
	void		*data;
};
EXPORT_FUNCTION int push_node_data( struct node **root, void *data );
EXPORT_FUNCTION void *pop_node_data( struct node **root);
EXPORT_FUNCTION void *get_node_data( struct node *root, int index);
EXPORT_FUNCTION void *remove_node( struct node **root, int index);
EXPORT_FUNCTION int get_node_count( struct node *node );





/***********************************************************************/
/* objectnum utility functions. */
/***********************************************************************/
struct objectNum
{
	char		 *name;
	unsigned int 	 num;
	struct objectNum *next;
};
EXPORT_FUNCTION int add_objectNum( char *name, unsigned int i );
EXPORT_FUNCTION int get_objectNextNum( char *name, unsigned int *i );




/***********************************************************************/
/* parameter structure & utility functions. */
/***********************************************************************/
/*error code*/
#define ERR_9000	-9000	/*Method not supported*/
#define ERR_9001	-9001	/*Request denied*/
#define ERR_9002	-9002	/*Internal error*/
#define ERR_9003	-9003	/*Invalid arguments*/
#define ERR_9004	-9004	/*Resources exceeded*/
#define ERR_9005	-9005	/*Invalid parameter name*/
#define ERR_9006	-9006	/*Invalid parameter type*/
#define ERR_9007	-9007	/*Invalid parameter value*/
#define ERR_9008	-9008	/*Attempt to set a non-writable parameter*/
#define ERR_9009	-9009	/*Notification request rejected*/
#define ERR_9010	-9010	/*Download failure*/
#define ERR_9011	-9011	/*Upload failure*/
#define ERR_9012	-9012	/*File transfer server authentication failure*/
#define ERR_9013	-9013	/*Unsupported protocol for file transfer*/
#define ERR_9801	-9801
#define ERR_9802	-9802
#define ERR_9803	-9803
#define ERR_9804	-9804
#define ERR_9811	-9811
#define ERR_9812	-9812
#define ERR_9813	-9813
#define ERR_9814	-9814
#define ERR_9821	-9821

/*sCWMP_ENTITY's flag value*/
#define CWMP_NTF_OFF	0x0000
#define CWMP_NTF_PAS	0x0001
#define CWMP_NTF_ACT	0x0002
#define CWMP_NTF_MASK	( CWMP_NTF_PAS  | CWMP_NTF_ACT )
#define CWMP_NTF_FORCED	0x0008  /*special: forced notification*/
#define CWMP_NTF_ALL_MASK ( CWMP_NTF_MASK | CWMP_NTF_FORCED )

#define CWMP_ACS_OFF	0x0000
#define CWMP_ACS_SUB	0x0010
#define CWMP_ACS_MASK	( CWMP_ACS_SUB ) 

#define	CWMP_WRITE	0x0100
#define	CWMP_READ	0x0200

#define CWMP_LNKLIST	0x1000

#define CWMP_DENY_ACT	0x2000
/*end sCWMP_ENTITY's flag value*/



typedef enum
{
	eCWMP_tNONE			= 0,
	eCWMP_tSTRING		= SOAP_TYPE_string,
	eCWMP_tARR_STRING	= SOAP_TYPE_ArrayOfStrings,
	eCWMP_tINT			= SOAP_TYPE_int,
	eCWMP_tUINT			= SOAP_TYPE_unsignedInt,
	eCWMP_tBOOLEAN		= SOAP_TYPE_xsd__boolean,
	eCWMP_tDATETIME		= SOAP_TYPE_time,
	eCWMP_tBASE64		= SOAP_TYPE_xsd__base64,
	eCWMP_tOBJECT		= 500, //for other purposes
	eCWMP_tINITOBJ		= 501,
	eCWMP_tADDOBJ		= 502,
	eCWMP_tDELOBJ		= 503,
	eCWMP_tUPDATEOBJ	= 504	
} eCWMP_TYPE;

struct sCWMP_ENTITY{
	char			name[64];
	eCWMP_TYPE		type;
	unsigned int		flag;
	char			*accesslist;
	/*getvalue->add/delobject and setvalue->createobject as the entity is a writable object*/
	int			(*getvalue)(char *name, struct sCWMP_ENTITY *entity, int *type, void **data);
	int			(*setvalue)(char *name, struct sCWMP_ENTITY *entity, int type, void *data);
	struct sCWMP_ENTITY	*next_table;
	struct sCWMP_ENTITY	*sibling;
};

#include "cwmplib.h"

EXPORT_FUNCTION int init_ParameterTable( struct sCWMP_ENTITY **root, struct sCWMP_ENTITY table[], char *prefix );
EXPORT_FUNCTION int destroy_ParameterTable( struct sCWMP_ENTITY *table);

EXPORT_FUNCTION int create_Object( struct sCWMP_ENTITY **table, struct sCWMP_ENTITY ori_table[], int size, int num, int from);
EXPORT_FUNCTION int add_Object( char *name, struct sCWMP_ENTITY **table, struct sCWMP_ENTITY ori_table[], int size, unsigned int *num);
EXPORT_FUNCTION int del_Object( char *name, struct sCWMP_ENTITY **table, int num);

EXPORT_FUNCTION int add_SiblingEntity( struct sCWMP_ENTITY **table, struct sCWMP_ENTITY *new_entity );
EXPORT_FUNCTION struct sCWMP_ENTITY *remove_SiblingEntity( struct sCWMP_ENTITY **table, unsigned int num);



/*******************************************************************/
/*  Interface APIs */
/*******************************************************************/
EXPORT_FUNCTION int init_Parameter(void);
EXPORT_FUNCTION int free_Parameter(void);
EXPORT_FUNCTION int update_Parameter(void);

EXPORT_FUNCTION int get_ParameterEntity( char *name, struct sCWMP_ENTITY **entity );

EXPORT_FUNCTION int get_ParameterName( char *prefix, int next_level, char **name );
EXPORT_FUNCTION int get_ParameterNameCount( char *prefix, int next_level );

EXPORT_FUNCTION int get_ParameterIsWritable( char *name, int *isW );
EXPORT_FUNCTION int get_ParameterIsReadable( char *name, int *isR );

EXPORT_FUNCTION int get_ParameterValue( char *name, int *type, void **value );
// return < 0: error,  = 0: had applied, > 0: had not appllied
EXPORT_FUNCTION int set_ParameterValue( char *name, int type, void *value );
/*set_PrivateParameterValue: parameters can be written by CPE itself, not by ACS*/
/*ex. parameters like ParameterKey, ConnectionRequestURL, and etc.*/
EXPORT_FUNCTION int set_PrivateParameterValue( char *name, int type, void *value );

EXPORT_FUNCTION int get_ParameterNotification( char *name, int *value );
EXPORT_FUNCTION int set_ParameterNotification( char *name, int value );

EXPORT_FUNCTION int get_ParameterAccessList( char *name, unsigned int *access );
EXPORT_FUNCTION int set_ParameterAccessList( char *name, unsigned int access );

// return < 0: error,  = 0: had applied, > 0: had not appllied
EXPORT_FUNCTION int add_ParameterObject( char *name, unsigned int *number );
// return < 0: error,  = 0: had applied, > 0: had not appllied
EXPORT_FUNCTION int del_ParameterObject( char *name );


/*******************************************************************/
/*  Utility APIs */
/*******************************************************************/
EXPORT_FUNCTION int *intdup( int value );
EXPORT_FUNCTION unsigned int *uintdup( unsigned int value );
EXPORT_FUNCTION int *booldup( int value);
EXPORT_FUNCTION time_t *timedup( time_t value);

EXPORT_FUNCTION void save2flash_reboot(int reboot_flag, int apply); //APACRTL-483
EXPORT_FUNCTION void factoryreset_reboot(void);

/*******************************************************************/
/* APIs for creating threads */
/*******************************************************************/
EXPORT_FUNCTION int gStartDSLDiag;
EXPORT_FUNCTION void cwmpStartDSLDiag(void);

EXPORT_FUNCTION void empty_data(int type, void **data);

#ifdef __cplusplus
}
#endif

#endif /* __PARAMETER_API_H__ */

