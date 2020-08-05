#include <bcmnvram.h>
#include "cwmp_notify.h"

#ifdef __DAVO__
#define CONFIG_DIR	"/tmp"
#else /* ORI */
#define CONFIG_DIR	"/var/config"
#endif
#define	NOTIFY_FILENAME	CONFIG_DIR"/CWMPNotify.txt"

struct CWMP_NOTIFY *pCWMPNotifyRoot=NULL;

struct CWMP_NOTIFY *notify_malloc(void)
{
	struct CWMP_NOTIFY *p=NULL;
	
	CWMPDBG( 3, ( stdout, "<%s:%d>\n", __FUNCTION__, __LINE__ ) );
	p = (struct CWMP_NOTIFY *)malloc( sizeof(struct CWMP_NOTIFY) );
	if(p)
	{
		p->name = NULL;
		p->type = 0;
		p->value = NULL;
		p->mode = 0;
		p->next = 0;
	}
	return p;
}

int notify_add( struct CWMP_NOTIFY **root, char *name, int type, void *value, unsigned int mode )
{
	struct CWMP_NOTIFY *p;
	
	CWMPDBG( 3, ( stdout, "<%s:%d>\n", __FUNCTION__, __LINE__ ) );
	if( (root==NULL) || (name==NULL) ) return -1;

	p=notify_malloc();
	if(p)
	{
		p->name = strdup( name );
		p->type = type;
		p->value = value;//malloc????
		p->mode = mode;

		if( *root )
		{
			struct CWMP_NOTIFY *c;
			c = *root;
			while( c->next ) c=c->next;
			c->next = p;
		}else
			*root = p;
			
		return 0;
	}
	return -1;
}

struct CWMP_NOTIFY *notify_find( struct CWMP_NOTIFY **root, char *name )
{
	struct CWMP_NOTIFY *p=NULL;
	
	CWMPDBG( 3, ( stdout, "<%s:%d>\n", __FUNCTION__, __LINE__ ) );
	if( root==NULL || name==NULL ) return NULL;
	
	p = *root;
	while( p )
	{
		if( nv_strcmp( p->name, name )==0 ) break;
		p = p->next;
	}
	
	return p;
}

int notify_delete( struct CWMP_NOTIFY **root, char *name )
{
	struct CWMP_NOTIFY *p=NULL, *pre=NULL;
	
	CWMPDBG( 3, ( stdout, "<%s:%d>\n", __FUNCTION__, __LINE__ ) );
	if( root==NULL || name==NULL ) return -1;

	p = *root;
	while( p )
	{
		if( nv_strcmp( p->name, name )==0 ) break;
		pre = p;
		p = p->next;
	}
	
	if(p)
	{
		if( pre )
			pre->next = p->next;
		else
			*root = p->next;
			
		if(p->name) free(p->name);
		if(p->value) free(p->value);
		free(p);
	}
	
	return 0;
}

int notify_check_equal( int type, void *data1, void *data2)
{
	int ret=0;
	
	CWMPDBG( 3, ( stdout, "<%s:%d>\n", __FUNCTION__, __LINE__ ) );
	if( data1==NULL && data2==NULL ) return 1; //????
	if( data1==NULL || data2==NULL ) return 0; //????
	
	//data1!=NULL , data2!=NULL
	switch( type )
	{
	case SOAP_TYPE_string:
		{
			char *st1=data1, *st2=data2;
			if( nv_strcmp( st1, st2 )==0 ) ret = 1;
		}
		break;
	case SOAP_TYPE_int:
	case SOAP_TYPE_xsd__boolean:
		{
			int *int1=data1, *int2=data2;
			if( *int1 == *int2 ) ret = 1;
		}
		break;
	case SOAP_TYPE_unsignedInt:
		{
			unsigned int *uint1=data1, *uint2=data2;
			if( *uint1 == *uint2 ) ret = 1;
		}
		break;
	case SOAP_TYPE_time:
		{
			time_t *t1=data1, *t2=data2;
			if( *t1 == *t2 ) ret = 1;
		}
		break;
//	case SOAP_TYPE_xsd__base64: //need data's size value
//		break;

	default:
		break;
	}
	
	return ret;
}

int notify_check( struct CWMP_NOTIFY **root, unsigned int mode )
{
	struct CWMP_NOTIFY *p=NULL;
	
	CWMPDBG( 3, ( stdout, "<%s:%d>\n", __FUNCTION__, __LINE__ ) );
	if( root==NULL ) return -1;

	p = *root;
	while(p)
	{
		if( ( (mode & CWMP_NTF_PAS)==(p->mode&CWMP_NTF_MASK) ) ||
		    ( (mode & CWMP_NTF_ACT)==(p->mode&CWMP_NTF_MASK) ) )
		{
			int type;
			void *data = NULL;

			if( get_ParameterValue( p->name, &type, &data )==0 )
			{
				if( notify_check_equal( type, data, p->value )==0 )
				{
					CWMPDBG(3, ( stdout, "<%s>%s's value was changed\n", __FUNCTION__, p->name));
					free(data);
					return 1;
				}else
					free(data);
			}//else when ret=error???			
		}
		
		p = p->next;
	}
	return 0;
}


/***********************************************************************/
/***     notify api    *************************************************/
/***********************************************************************/
int notify_load( void )
{
	FILE *fp;
	
	fp = fopen( NOTIFY_FILENAME, "r" );
	if(fp)
	{
		char tmp[MAX_PRMT_NAME_LEN+16];
		char name[MAX_PRMT_NAME_LEN];
		unsigned int  mode;
		
		while( fgets(tmp,sizeof(tmp),fp) )
		{
			if( sscanf( tmp, "%127s %u", name, &mode )==2 )
			{
				unsigned int nm=0, am=0;

				CWMPDBG( 2, ( stdout, "<%s:%d>Loading <name:%s><mode:0x%x>\n", __FUNCTION__, __LINE__, name, mode ) );
				nm = mode&CWMP_NTF_ALL_MASK;
				if(nm==0) nm = CWMP_NTF_MASK;				
				am = mode&CWMP_ACS_MASK;
				if(am==0) am = CWMP_ACS_MASK;
				notify_update( name, nm , am );
			}
		}
		fclose(fp);
	}else
		CWMPDBG( 0, ( stdout, "<%s:%d>Open Read %s error\n", __FUNCTION__, __LINE__, NOTIFY_FILENAME ) );
	
	return 0;
}

int notify_save( int Save2Flash )
{
	struct CWMP_NOTIFY *c=pCWMPNotifyRoot;
	FILE *fp;
	
	fp = fopen( NOTIFY_FILENAME, "w" );
	if(fp)
	{
		while( c )
		{
			fprintf( fp, "%s %u\n", c->name, c->mode);
			c = c->next;
		}
		
		fclose(fp);
	}else
		CWMPDBG( 0, ( stdout, "<%s:%d>Open %s error\n", __FUNCTION__, __LINE__, NOTIFY_FILENAME ) );
		
#ifdef __REALTEK__
	if(Save2Flash)
	{
		if( va_cmd( "/bin/flatfsd",1,1,"-s" ) )
			CWMPDBG( 0, ( stdout, "<%s:%d>exec 'flatfsd -s' error!\n", __FUNCTION__, __LINE__ ) );
	}
#endif /* __REALTEK__ */
	
	return 0;
}

int notify_init(int isNat)
{
	//char *name=NULL;

	CWMPDBG( 3, ( stdout, "<%s:%d>\n", __FUNCTION__, __LINE__ ) );

	//forced inform parameters
/*	
	notify_update( "InternetGatewayDevice.DeviceSummary", CWMP_NTF_FORCED|CWMP_NTF_PAS, CWMP_ACS_MASK );
	notify_update( "InternetGatewayDevice.DeviceInfo.ModelName", CWMP_NTF_FORCED|CWMP_NTF_PAS, CWMP_ACS_MASK );
	notify_update( "InternetGatewayDevice.DeviceInfo.SpecVersion", CWMP_NTF_FORCED|CWMP_NTF_PAS, CWMP_ACS_MASK );
	notify_update( "InternetGatewayDevice.DeviceInfo.HardwareVersion", CWMP_NTF_FORCED|CWMP_NTF_PAS, CWMP_ACS_MASK );
	notify_update( "InternetGatewayDevice.DeviceInfo.SoftwareVersion", CWMP_NTF_FORCED|CWMP_NTF_ACT, CWMP_ACS_MASK );
	notify_update( "InternetGatewayDevice.DeviceInfo.ProvisioningCode", CWMP_NTF_FORCED|CWMP_NTF_ACT, CWMP_ACS_MASK );
	notify_update( "InternetGatewayDevice.ManagementServer.ParameterKey", CWMP_NTF_FORCED|CWMP_NTF_PAS,CWMP_ACS_MASK  );

	notify_update( "InternetGatewayDevice.ManagementServer.ConnectionRequestURL", CWMP_NTF_FORCED|CWMP_NTF_ACT, CWMP_ACS_MASK  );
	if (isNat) 
		notify_update( "InternetGatewayDevice.ManagementServer.UDPConnectionRequestAddress", CWMP_NTF_FORCED|CWMP_NTF_ACT, CWMP_ACS_MASK  ); */
	notify_update( "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.AddressingType", CWMP_NTF_FORCED|CWMP_NTF_ACT, CWMP_ACS_MASK  );
	notify_update( "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.ExternalIPAddress", CWMP_NTF_FORCED|CWMP_NTF_ACT, CWMP_ACS_MASK  );

	notify_load();
	
	return 0;
}

int notify_uninit( void )
{
	struct CWMP_NOTIFY *c;

	CWMPDBG( 3, ( stdout, "<%s:%d>\n", __FUNCTION__, __LINE__ ) );	
	//if( root==NULL ) return -1;
	
	c = pCWMPNotifyRoot;
	while( c )
	{
		struct CWMP_NOTIFY *n = c->next;
		
		CWMPDBG( 2, ( stdout, "<%s:%d>free %s\n", __FUNCTION__, __LINE__, c->name ) );	
		if( c->name ) free( c->name );
		if( c->value ) free( c->value );
		free( c );
		
		c = n;
	}
	pCWMPNotifyRoot = NULL;
	return 0;
}

int notify_modify( char *name, unsigned int mode  )
{
	int type=eCWMP_tNONE;
	void *data = NULL;
	//int ret;
	struct CWMP_NOTIFY **root= &pCWMPNotifyRoot;
	struct CWMP_NOTIFY *pNotify;
	
	CWMPDBG( 3, ( stdout, "<%s:%d>name:%s, mode:0x%x\n", __FUNCTION__, __LINE__, name, mode ) );
	if( (root==NULL) || (name==NULL) ) return -1;

	pNotify = notify_find( root, name );
	if( pNotify==NULL )
	{
		if(mode!=0)
		{
			if( mode&CWMP_NTF_ALL_MASK )
				get_ParameterValue( name, &type, &data );
			return notify_add( root, name, type, data, mode );
		}else //mode==0 ==>nothing to do
			return 0;
	}else
	{
		// the name is in the notify list
		if(mode==0)
		{
			return notify_delete( root, name );
		}else if( mode & CWMP_NTF_ALL_MASK ){
			if(pNotify->type ==eCWMP_tNONE)
			{
				get_ParameterValue( name, &type, &data );
				pNotify->type = type;
				pNotify->value = data;
			}
			pNotify->mode = mode;
			return 0;
		}else{
			pNotify->mode = mode;
			pNotify->type = eCWMP_tNONE;
			if(pNotify->value)
			{
				free(pNotify->value);
				pNotify->value=NULL;
			}
			return 0;
		}
	}
	return 0;
}

/*notify_mode==CWMP_NTF_MASK or access_mode==CWMP_ACS_MASK means no change*/
int notify_update( char *name, unsigned int notify_mode, unsigned int access_mode  )
{
	struct sCWMP_ENTITY *p;
	struct CWMP_NOTIFY **root= &pCWMPNotifyRoot;
	struct CWMP_NOTIFY *pNotify;
	unsigned int new_mode=0;

	CWMPDBG( 3, ( stdout, "<%s:%d> %s:%u:%u\n", __FUNCTION__, __LINE__,name, notify_mode, access_mode ) );
	if( get_ParameterEntity( name, &p ) < 0 ) return ERR_9005;
	if( (p!=NULL) && ( p->type==eCWMP_tOBJECT ) ) return ERR_9003;

	pNotify = notify_find( root, name );
	notify_mode = notify_mode & CWMP_NTF_ALL_MASK;
	access_mode = access_mode & CWMP_ACS_MASK;
	if(pNotify)
	{
		unsigned int old_notify;
		unsigned int old_access;
		
		old_notify = pNotify->mode & CWMP_NTF_ALL_MASK;
		if( notify_mode != CWMP_NTF_MASK )
		{
			if( notify_mode != old_notify)
				set_ParameterNotification( name, notify_mode & CWMP_NTF_MASK );
			new_mode = new_mode | notify_mode | (old_notify & CWMP_NTF_FORCED);
		}else //keep the old setting
			new_mode = new_mode | old_notify;
		
		old_access = pNotify->mode & CWMP_ACS_MASK;
		if( access_mode != CWMP_ACS_MASK )
		{
			if( access_mode != old_access )
				set_ParameterAccessList( name, access_mode );
			new_mode = new_mode | access_mode;
		}else //keep the old setting
			new_mode = new_mode | old_access;
			
		if( new_mode==pNotify->mode ) return 0;

	}else
	{
		if( notify_mode != CWMP_NTF_MASK ) 
		{
			set_ParameterNotification( name, notify_mode & CWMP_NTF_MASK );
			new_mode = new_mode | notify_mode;
		}
		
		if( access_mode != CWMP_ACS_MASK )
		{
			set_ParameterAccessList( name, access_mode );
			new_mode = new_mode | access_mode;
		}
		
		if( new_mode==0) return 0;				
	}
	
	return notify_modify( name, new_mode );
}

int notify_update_value( char *name )
{
	int type;
	void *data = NULL;
	int ret;
	struct CWMP_NOTIFY **root= &pCWMPNotifyRoot;
	struct CWMP_NOTIFY *pNotify;

	CWMPDBG( 2, ( stdout, "<%s:%d>\n", __FUNCTION__, __LINE__ ) );
	if( root==NULL ) return 0;

	pNotify = notify_find( root, name );
	if( pNotify==NULL ) return 0;
	if( (pNotify->mode&CWMP_NTF_ALL_MASK )==CWMP_NTF_OFF ) return 0;

	//get the type & value
	ret = get_ParameterValue( name, &type, &data );
	if( ret!=0 )
	{
		CWMPDBG( 1, ( stdout, "<%s:%d>Can't get %s 's value(err:%d)\n", __FUNCTION__, __LINE__, name, ret ) );
		return -1;
	}
	
	pNotify->type = type;
	if(pNotify->value) free(pNotify->value);
	pNotify->value=data;

	return 0;
}

int notify_check_active( void )
{
	struct CWMP_NOTIFY **root= &pCWMPNotifyRoot;
	CWMPDBG( 3, ( stdout, "<%s:%d>\n", __FUNCTION__, __LINE__ ) );
	return notify_check( root, CWMP_NTF_ACT );
}

int notify_check_passive( void )
{
	struct CWMP_NOTIFY **root= &pCWMPNotifyRoot;
	CWMPDBG( 3, ( stdout, "<%s:%d>\n", __FUNCTION__, __LINE__ ) );
	return notify_check( root, CWMP_NTF_PAS );
}

int notify_check_all( void )
{
	int ret;
	struct CWMP_NOTIFY **root= &pCWMPNotifyRoot;
	ret =  notify_check( root, CWMP_NTF_ACT|CWMP_NTF_PAS );
	CWMPDBG( 1, ( stdout, "<%s:%d> return %d\n", __FUNCTION__, __LINE__ , ret) );
	return ret;
}

int notify_check_if_exist( struct node *root, struct CWMP_NOTIFY *p )
{
	int count, i;
	
	CWMPDBG( 3, ( stdout, "<%s:%d>\n", __FUNCTION__, __LINE__ ) );
	if( p==NULL || root==NULL ) return 0;
	
	count = get_node_count( root );
	for( i=0;i<count;i++ )
	{
		struct CWMP_NOTIFY *c;
		c = (struct CWMP_NOTIFY *)get_node_data( root, i );
		if( c==p ) return 1;
	}
	return 0;
	
}

int notify_check_valid( struct CWMP_NOTIFY **notify_root, struct node **node_root )
{
	struct CWMP_NOTIFY *notify, *c;
	struct node **node;
	int found;
	
	CWMPDBG( 3, ( stdout, "<%s:%d>\n", __FUNCTION__, __LINE__ ) );	
	if( node_root==NULL || notify_root==NULL ) return 0;

	node = node_root;
	while( *node )
	{
		c = (*node)->data;
		notify = *notify_root;
		found=0;
		while( notify )
		{
			if( notify==c )
			{
				found=1;
				break;
			}
			notify = notify->next;	
		}
		
		if( found==0 )
		{
			struct node *delete_node;
			delete_node = *node;
			*node = (*node)->next;
			free( delete_node );
		}else
			node = & (*node)->next;
		
	}
	return 0;
}

int notify_create_update_info( struct node **node_root )
{
	struct CWMP_NOTIFY **root= &pCWMPNotifyRoot;
	struct CWMP_NOTIFY *p=NULL;
	int new_list=1;

	CWMPDBG( 3, ( stdout, "<%s:%d>\n", __FUNCTION__, __LINE__ ) );
	if( root==NULL || node_root==NULL ) return -1;

	if( *node_root )
	{
		new_list = 0;
		notify_check_valid( root, node_root );
	}

	p = *root;
	while(p)
	{
		int type;
		void *data = NULL;

		if( p->mode & CWMP_NTF_ALL_MASK )
		{
			if( get_ParameterValue( p->name, &type, &data )==0 )
			{
				//check if p has been in the list
				if(  (new_list==1) || (notify_check_if_exist( *node_root, p )==0) )
				{			
					if( notify_check_equal( type, data, p->value )==0 )
					{
						if(p->value) free(p->value);
						p->value = data;
						p->type = type;
						
						push_node_data( node_root, p );//only add the pointer of struct CWMP_NOTIFY to node_root
					}else
					{
						if( p->mode & CWMP_NTF_FORCED ) //forced inform parameters
							push_node_data( node_root, p );//only add the pointer of struct CWMP_NOTIFY to node_root
						free(data);
					}
				}else
					free(data);
			}//else when ret=error??? skip??
		}
		
		p = p->next;
	}	
	
	return 0;
}
