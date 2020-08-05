#ifndef __PRMT_OBJSAMPLE_C__
#define __PRMT_OBJSAMPLE_C__

#include <stdio.h>
#include <string.h>
#include <bcmnvram.h>
#include "prmt_objsample.h"
#include "bcm_cfg_api.h"

struct sCWMP_ENTITY tOBJENTITY[] =
{
	/*(name, 	type,       	flag,           		accesslist, getvalue,   		setvalue,   	next_table, sibling)*/
	{"Entity01",eCWMP_tBOOLEAN, CWMP_WRITE|CWMP_READ,   NULL,       getOBJENTITY, 		setOBJENTITY, 	NULL,     	NULL},
	{"Entity02",eCWMP_tUINT,    CWMP_WRITE|CWMP_READ|CWMP_DENY_ACT,NULL,getOBJENTITY,	setOBJENTITY, 	NULL,     	NULL},
	{"Entity03",eCWMP_tSTRING,  CWMP_WRITE|CWMP_READ,   NULL,       getOBJENTITY, 		setOBJENTITY, 	NULL,     	NULL},
	{"", 		eCWMP_tNONE,    0,          			NULL,       NULL, 				NULL,       	NULL, 		NULL}
};

struct sCWMP_ENTITY tOBJMAP[] =
{
	/*(name,            type,       	flag,           			accesslist, 	getvalue,   setvalue,   next_table, sibling)*/
	{"0",             eCWMP_tOBJECT,  CWMP_READ|CWMP_WRITE|CWMP_LNKLIST,  NULL, 	NULL,       NULL,       tOBJENTITY, NULL},
	{"", eCWMP_tNONE, 0, NULL, NULL, NULL, NULL, NULL}
};

struct sCWMP_ENTITY tObjSample[] =
{
	/*(name,			type,			flag,					accesslist,	getvalue,		setvalue,		next_table,		sibling)*/
	{"Obj",				eCWMP_tOBJECT,	CWMP_READ|CWMP_WRITE,	NULL,		NULL,			ObjMethodSample,NULL,			NULL},
	{"",				eCWMP_tNONE,	0,						NULL,		NULL,			NULL,			NULL,			NULL}
};

/**************************************************************************************/
/* utility functions*/
/**************************************************************************************/
int getChainID( struct sCWMP_ENTITY *ctable, int num )
{
	int id=-1;
	char buf[32];

	snprintf( buf, sizeof(buf), "%d", num );
	while( ctable )
	{
		id++;
		if( nv_strcmp(ctable->name, buf)==0 )
			break;
		ctable = ctable->sibling;
	}
	return id;
}

/**************************************************************************************/
/* obj method sample functions*/
/**************************************************************************************/
int ObjMethodSample(char *name, struct sCWMP_ENTITY *entity, int type, void *data)
{
	fprintf( stderr, "%s:action:%d: %s\n", __FUNCTION__, type, name);fflush(NULL);

	switch( type ) {    
		case eCWMP_tINITOBJ:
			{    
				int num=0,MaxInstNum=0,i;
				struct sCWMP_ENTITY **c = (struct sCWMP_ENTITY **)data;
				OBJ_SAMPLE_T *p, obj_entity;

				if( (name==NULL) || (entity==NULL) || (data==NULL) ) return -1;

				num = cwmp_cfg_chain_total( CWMP_OBJ_SAMPLE_TBL );
				for( i=0; i<num;i++ )
				{    
					p = &obj_entity;
					if( cwmp_cfg_chain_get( CWMP_OBJ_SAMPLE_TBL, i, p, sizeof(OBJ_SAMPLE_T) ) )
						continue;

					if( p->InstanceNum==0 ) //maybe createn by web or cli
					{    
						MaxInstNum++;
						p->InstanceNum = MaxInstNum;
						cwmp_cfg_chain_update( CWMP_OBJ_SAMPLE_TBL, i, p, sizeof(OBJ_SAMPLE_T)); 
					}else
						MaxInstNum = p->InstanceNum;
					if( create_Object( c, tOBJMAP, sizeof(tOBJMAP), 1, MaxInstNum ) < 0 )
						return -1;
					//c = & (*c)->sibling;
				}    
				add_objectNum( name, MaxInstNum );

				return 0;
			}    

		case eCWMP_tADDOBJ:
			{
				int ret; 

				if( (name==NULL) || (entity==NULL) || (data==NULL) ) return -1;

				ret = add_Object( name, &entity->next_table,  tOBJMAP, sizeof(tOBJMAP), data );
				if( ret >= 0 )
				{    
					OBJ_SAMPLE_T entry;

					memset( &entry, 0, sizeof(OBJ_SAMPLE_T) );
					{ //default values for this new entry
						entry.InstanceNum= *(int*)data;
						entry.param=1;

					}
					cwmp_cfg_chain_add( CWMP_OBJ_SAMPLE_TBL, (unsigned char*)&entry, sizeof(OBJ_SAMPLE_T) );
				}

				return ret;
			}

		case eCWMP_tDELOBJ:
			{
				int ret, id;

				if( (name==NULL) || (entity==NULL) || (data==NULL) ) return -1;

				id = getChainID( entity->next_table, *(int*)data  );
				if(id==-1) return ERR_9005;
				cwmp_cfg_chain_delete( CWMP_OBJ_SAMPLE_TBL, id);
				ret = del_Object( name, &entity->next_table, *(int*)data );
				if(ret==0) ret=1;

				return ret;
			}

		case eCWMP_tUPDATEOBJ:
			{
				int num=0,i;
				struct sCWMP_ENTITY *old_table;

				num = cwmp_cfg_chain_total( CWMP_OBJ_SAMPLE_TBL );
				old_table = entity->next_table;
				entity->next_table = NULL;
				for( i=0; i<num;i++ )
				{
					struct sCWMP_ENTITY *remove_entity=NULL;
					OBJ_SAMPLE_T *p, obj_entity;

					p = &obj_entity;
					if( cwmp_cfg_chain_get( CWMP_OBJ_SAMPLE_TBL, i, p, sizeof(OBJ_SAMPLE_T) )<0 )
						continue;

					remove_entity = remove_SiblingEntity( &old_table, p->InstanceNum );
					if( remove_entity!=NULL )
					{
						add_SiblingEntity( &entity->next_table, remove_entity );
					}else{
						unsigned int MaxInstNum=p->InstanceNum;

						add_Object( name, &entity->next_table,  tOBJMAP, sizeof(tOBJMAP), &MaxInstNum );
						if(MaxInstNum!=p->InstanceNum)
						{
							p->InstanceNum = MaxInstNum;
							cwmp_cfg_chain_update( CWMP_OBJ_SAMPLE_TBL, i, p, sizeof(OBJ_SAMPLE_T) );
						}
					}
				}

				if( old_table )
					destroy_ParameterTable( old_table );
				return 0;
			}

		default:
			break;
	}

	return -1;
}

int getOBJENTITY(char *name, struct sCWMP_ENTITY *entity, int *type, void **data)
{
	fprintf(stderr, "[%s():%d] TODO\n", __FUNCTION__, __LINE__);
	return 0;
}

int setOBJENTITY(char *name, struct sCWMP_ENTITY *entity, int type, void *data)
{
	fprintf(stderr, "[%s():%d] TODO\n", __FUNCTION__, __LINE__);
	return 0;
}

#endif /* __PRMT_OBJSAMPLE_C__ */

