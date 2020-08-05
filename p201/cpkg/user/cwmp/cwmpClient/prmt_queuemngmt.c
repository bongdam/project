#ifndef __PRMT_QUEUEMNGMT_C__
#define __PRMT_QUEUEMNGMT_C__

#include <stdio.h>
#include <string.h>
#include <bcmnvram.h>
#include "prmt_queuemngmt.h"
#include "bcm_param_api.h"

struct sCWMP_ENTITY tQueueMngmt[] = {
	/*(name,				type,			flag,	 				accesslist,	getvalue,					setvalue,					next_table,	sibling)*/
	{"",					eCWMP_tNONE,	0,						NULL,		NULL,			NULL,			NULL,			NULL}
};

#endif /* __PRMT_QUEUEMNGMT_C__ */
