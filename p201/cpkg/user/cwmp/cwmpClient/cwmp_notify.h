#ifndef _CWMP_NOTIFY_H_
#define _CWMP_NOTIFY_H_

#include "parameter_api.h"



#ifdef __cplusplus
extern "C" {
#endif


struct CWMP_NOTIFY{
	char			*name;
	int			type;
	void			*value;
	unsigned int		mode;
	struct CWMP_NOTIFY	*next;
};

extern struct CWMP_NOTIFY *pCWMPNotifyRoot;

extern int notify_init( int );
extern int notify_uninit( void );
extern int notify_modify( char *name, unsigned int mode  );
/*notify_update: call notify_modify & modify the CWMP_NOTIFY_TBL chain*/
extern int notify_update( char *name, unsigned int notify_mode, unsigned int access_mode  );
extern int notify_update_value( char *name );
extern int notify_check_active( void );
extern int notify_check_passive( void );
extern int notify_check_all( void );
extern int notify_create_update_info( struct node **node_root );
extern int notify_save( int Save2Flash );
#ifdef __cplusplus
}
#endif

#endif /*_CWMP_NOTIFY_H_*/
