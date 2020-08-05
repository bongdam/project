/*
 *      Web server handler routines for HTTP URL Redirect
 *
 *
 */

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <ctype.h>
#include <signal.h>

#include "boa.h"
#include "asp_page.h"
#include "apmib.h"
#include "apform.h"
#include "utility.h"

void formHttpRedirect(request *wp, char *path, char *query)
{	
	int i, enabled=0;
	char *tmpStr, *submitUrl ;
	char tmpBuf[100];
	
	tmpStr = req_get_cstream_var(wp, "redirectEnabled", "");  
	if(!strcmp(tmpStr, "ON"))
		enabled = 1 ;
	else 
		enabled = 0 ;

	if ( apmib_set( MIB_HTTP_REDIRECT_ENABLED, (void *)&enabled) == 0) {
		strcpy(tmpBuf, "Set MIB_HTTP_REDIRECT_ENABLED error!");
		goto setErr;
	}
	
	if(enabled){
		tmpStr = req_get_cstream_var(wp, "redirectUrl", "");  
		if(tmpStr[0]){
			for(i=0; tmpStr[i]!='\0'; i++)
				tmpStr[i] = tolower(tmpStr[i]);
				
			if(strncmp(tmpStr, "http://", strlen("https://")) == 0){
				strcpy(tmpBuf, "Can't set https url!");
				goto setErr;
			}else if(strncmp(tmpStr, "http://", strlen("http://")) == 0)
				strcpy(tmpBuf, tmpStr+strlen("http://"));
			else
				strcpy(tmpBuf, tmpStr);
			
	 		if (apmib_set(MIB_HTTP_REDIRECT_URL, (void *)&tmpBuf) == 0) {
				strcpy(tmpBuf, "Set MIB_HTTP_REDIRECT_URL error!");
				goto setErr;
			}
			strcpy(tmpStr, tmpBuf);

			
			#ifdef CONFIG_RTL_HTTPS_REDIRECT
			/*Parse the host form URL*/		
			char *p = strstr(tmpStr, "/");
			if(p){
				memset(tmpBuf,0x00, sizeof(tmpBuf));
				memcpy(tmpBuf, tmpStr, p-tmpStr);
				tmpBuf[p-tmpStr] = '\0';
			}
		//	printf("[%s:%d] url_host=%s\n",__FUNCTION__,__LINE__, tmpBuf);
						
			if (apmib_set(MIB_HTTP_REDIRECT_HOST, (void *)&tmpBuf) == 0) {
				strcpy(tmpBuf, "Set MIB_HTTP_REDIRECT_HOST error!");
				goto setErr;
			}
			#endif
		}
	}

	apmib_update_web(CURRENT_SETTING);

#ifndef NO_ACTION
	tmpStr = req_get_cstream_var(wp, "save_apply", "");
	if(tmpStr[0])
		run_init_script("all");
#endif

	submitUrl = req_get_cstream_var(wp, "submit-url", "");	 // hidden page
	OK_MSG(submitUrl);
	return;

setErr:
	ERR_MSG(tmpBuf);
}

