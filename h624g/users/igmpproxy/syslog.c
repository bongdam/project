/*
**  smcroute - static multicast routing control 
**  Copyright (C) 2001 Carsten Schill <carsten@cschill.de>
**
**  This program is free software; you can redistribute it and/or modify
**  it under the terms of the GNU General Public License as published by
**  the Free Software Foundation; either version 2 of the License, or
**  (at your option) any later version.
**
**  This program is distributed in the hope that it will be useful,
**  but WITHOUT ANY WARRANTY; without even the implied warranty of
**  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
**  GNU General Public License for more details.
**
**  You should have received a copy of the GNU General Public License
**  along with this program; if not, write to the Free Software
**  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
**
**  $Id: syslog.c,v 1.1.1.1 2007-08-06 10:04:43 root Exp $	
**
**  This module contains the interface functions for syslog
**
*/

#include "mclab.h"
#ifdef __DAVO__
#include <time.h>

#define isspace(c) ((((c) == ' ') || (((unsigned int)((c) - 9)) <= (13 - 9))))

int Log2Stderr = ((1 << LOG_EMERG) || (1 << LOG_ERR) || (1 << LOG_WARNING));
int LogSeverityMask = (1 << LOG_EMERG) | (1 << LOG_INFO) | (1 << LOG_DEBUG);

void log(int Serverity, int Errno, const char *format, ...)
{
	va_list va;
	char buffer[128];
	char *p = buffer;
	int n, tst = 1 << Serverity;
	time_t now;
	struct tm tm;

	if ((tst & LogSeverityMask) || (tst & Log2Stderr)) {
		const char *E = (Errno <= 0) ? "" : strerror(Errno);

		va_start(va, format);
		n = vsnprintf(buffer, sizeof(buffer), format, va);
		if (n < (int)sizeof(buffer))
			p = buffer;
		else if ((p = (char *)malloc(n + 1)))
			vsnprintf(p, n + 1, format, va);
		va_end(va);

		if (p != NULL) {
			while (n > 0 && isspace(p[n - 1]))
				p[--n] = '\0';

			if (tst & Log2Stderr) {
				time(&now);
				localtime_r(&now, &tm);
				fprintf(stderr, "%02d:%02d:%02d %s%s%s\n",
					tm.tm_hour, tm.tm_min, tm.tm_sec, p, (E[0] ? ": " : ""), E);
			}

			if (tst & LogSeverityMask)
				syslog(Serverity, "%s%s%s", p, (E[0] ? ": " : ""), E);

			if (p != buffer)
				free(p);
		}
	}

	if (Serverity <= LOG_ERR)
		exit(-1);
}
#else	/* __DAVO__ */
int Log2Stderr = LOG_WARNING;

int  LogLastServerity;
int  LogLastErrno;
char LogLastMsg[ 128 ];

void log( int Serverity, int Errno, const char *FmtSt, ... )
/*
** Writes the message 'FmtSt' with the parameters '...' to syslog.
** 'Serverity' is used for the syslog entry. For an 'Errno' value 
** other then 0, the correponding error string is appended to the
** message.
**
** For a 'Serverity' more important then 'LOG_WARNING' the message is 
** also logged to 'stderr' and the program is finished with a call to 
** 'exit()'.
**
** If the 'Serverity' is more important then 'Log2Stderr' the message
** is logged to 'stderr'.
**          
*/
{
  const char ServVc[][ 5 ] = { "EMER", "ALER", "CRIT", "ERRO", 
			       "Warn", "Note", "Info", "Debu" };

  const char *ServPt = Serverity < 0 || Serverity >= VCMC( ServVc ) ? 
                       "!unknown serverity!" : ServVc[ Serverity ];
 
  const char *ErrSt = (Errno <= 0) ? NULL : (const char *)strerror( Errno ); 

  {
    va_list ArgPt;
    unsigned Ln;

    va_start( ArgPt, FmtSt );
    Ln  = snprintf( LogLastMsg, sizeof( LogLastMsg ), "%s: ", ServPt );
    Ln += vsnprintf( LogLastMsg + Ln, sizeof( LogLastMsg ) - Ln, FmtSt, ArgPt );
    if( ErrSt )
      snprintf( LogLastMsg + Ln, sizeof( LogLastMsg ) - Ln, "; Errno(%d): %s", Errno, ErrSt );
       
    va_end( ArgPt );
  }


  // update our global Last... variables
  LogLastServerity = Serverity;
  LogLastErrno = Errno;

  // control logging to stderr
  if( Serverity < LOG_WARNING || Serverity < Log2Stderr )
    fprintf( stderr, "%s\n", LogLastMsg );

  // always to syslog
  syslog( Serverity, "%s", LogLastMsg );
  //printf("%s\n", LogLastMsg);

  if( Serverity <= LOG_ERR )
    exit( -1 );
}
#endif
