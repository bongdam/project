/* src_snmp/snmp_config.h.  Generated automatically by configure.  */
#ifndef _snmp_config_h_
#define _snmp_config_h_

#ifdef WIN32

#define HAVE_ALLOCA_H
#define HAVE_CTYPE_H
#define HAVE_ERRNO_H
#define HAVE_IN_H
#define HAVE_IO_H
#define HAVE_MALLOC_H
#define HAVE_MEMORY_H
#define HAVE_NET_IF_H
#define HAVE_NETINET_IN_H
#define HAVE_SETJMP_H
#define HAVE_STDIO_H
#define HAVE_STDLIB_H
#define HAVE_STRING_H
#define HAVE_STRINGS_H
#define HAVE_SYS_FILE_H
#define HAVE_SYS_IOCTL_H
#define HAVE_SYS_SOCKET_H
#define HAVE_SYS_TIME_H
#define HAVE_SYS_TYPES_H
#define HAVE_TIME_H
#define HAVE_UNISTD_H
#define HAVE_WINSOCK_H

#else /* WIN32 not defined */

/* Define if you have the ANSI C header files.  */
#define STDC_HEADERS 1

/* Define if you have the <alloca.h> header file.  */
#define HAVE_ALLOCA_H 1

/* Define if you have the <errno.h> header file.  */
#define HAVE_ERRNO_H 1

/* Define if you have the <in.h> header file.  */
/* #undef HAVE_IN_H */

/* Define if you have the <io.h> header file.  */
/* #undef HAVE_IO_H */

/* Define if you have the <malloc.h> header file.  */
#define HAVE_MALLOC_H 1

/* Define if you have the <memory.h> header file.  */
#define HAVE_MEMORY_H 1

/* Define if you have the <net/if.h> header file.  */
#define HAVE_NET_IF_H 1

/* Define if you have the <netinet/in.h> header file.  */
#define HAVE_NETINET_IN_H 1

/* Define if you have the <setjmp.h> header file.  */
#define HAVE_SETJMP_H 1

/* Define if you have the <stdio.h> header file.  */
#define HAVE_STDIO_H 1

/* Define if you have the <strings.h> header file.  */
#define HAVE_STRINGS_H 1

/* Define if you have the <sys/file.h> header file.  */
#define HAVE_SYS_FILE_H 1

/* Define if you have the <sys/ioctl.h> header file.  */
#define HAVE_SYS_IOCTL_H 1

/* Define if you have the <sys/socket.h> header file.  */
#define HAVE_SYS_SOCKET_H 1

/* Define if you have the <sys/time.h> header file.  */
#define HAVE_SYS_TIME_H 1

/* Define if you have the <sys/types.h> header file.  */
#define HAVE_SYS_TYPES_H 1

/* Define if you have the <time.h> header file.  */
#define HAVE_TIME_H 1

/* Define if you have the <unistd.h> header file.  */
#define HAVE_UNISTD_H 1

/* Define if you have the <winsock.h> header file.  */
/* #undef HAVE_WINSOCK_H */

/* Define if you have the gcc library (-lgcc).  */
#define HAVE_LIBGCC 1
#endif /* WIN32 not defined */

#if defined(__STDC__) || defined(__GNUC__)
#define SNMP_VOID void
#else
#define SNMP_VOID
#endif

#ifdef DV_SNMP_DEBUG
#define SNMP_DEBUG(string)      printf("%s(%d): %s\n",__FILE__, __LINE__, string);
#else
#define SNMP_DEBUG(string)
#endif


#endif /* _snmp_config_h_ */
