#ifndef _snmp_string_h_
#define _snmp_string_h_

//#ifdef HAVE_CONFIG_H
#  include "snmp_config.h"
//#endif

#ifdef STDC_HEADERS
#  include <string.h>
#  ifndef bcopy
#    define bcopy(a,b,len) memcpy((b),(a),(len))
#  endif
#  ifndef bcmp 
#    define bcmp(a,b,len) memcmp((b),(a),(len))
#  endif
#  ifndef bzero
#    define bzero(ptr,len) memset((ptr),0,(len))
#  endif
#elif defined HAVE_STRINGS_H
#  include <strings.h>
#endif

#ifndef strcasecmp
#  define strcasecmp(a,b) snmp_strcasecmp((a),(b))
extern int snmp_strcasecmp (char *, char *);
#endif

#endif /* _snmp_string_h_ */
