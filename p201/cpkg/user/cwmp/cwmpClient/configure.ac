#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.65])
AC_INIT([cwmpClient], [VERSION], [BUG-REPORT-ADDRESS])
AC_CONFIG_SRCDIR([prmt_mngmtserver.c])
AC_CONFIG_HEADERS([config.h])

dnl AC_PROG_MAKE_SET

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_RANLIB
AM_INIT_AUTOMAKE

# Checks for libraries.
# FIXME: Replace `main' with a function in `-lcrypto':
#AC_CHECK_LIB([crypto], [main])
# FIXME: Replace `main' with a function in `-lgsoapck':
AC_CHECK_LIB([gsoapck], [main])
# FIXME: Replace `main' with a function in `-lgsoapssl':
AC_CHECK_LIB([gsoapssl], [main])
# FIXME: Replace `main' with a function in `-lm':
AC_CHECK_LIB([m], [main])
# FIXME: Replace `main' with a function in `-lnvram':
AC_CHECK_LIB([nvram], [main])
# FIXME: Replace `main' with a function in `-lpthread':
AC_CHECK_LIB([pthread], [main])
# FIXME: Replace `main' with a function in `-lshared':
AC_CHECK_LIB([shared], [main])
# FIXME: Replace `main' with a function in `-lssl':
#AC_CHECK_LIB([ssl], [main])


dnl Platform-specific Makefile setup
case "${host}" in
        *-*-solaris*)   platform=SUN_OS
            SAMPLE_EXTRA_LIBS="-lxnet -lsocket -lnsl"
            ;;
        *-*-sysv5*)     platform=UNIXWARE ;;
        *-*-UnixWare*)  platform=UNIXWARE ;;
        *-*-unixware*)  platform=UNIXWARE ;;
    *-*-sco3.2v5*)  platform=OPENSERVER
                    SAMPLE_EXTRA_LIBS="-lsocket"
            ;;
        *-*-linux*)     platform=LINUX
dnl         if test x$debug = xtrue; then 
dnl             CFLAGS="-g" #don't want the -O2 for debugging.
dnl         else
dnl             CFLAGS="-O2" #don't want the -g for release compile.
dnl         fi          
            ;;
    *-*-cygwin*)    platform=CYGWIN
            ;;
        *-*-freebsd*)   platform=FREEBSD ;;
        *-*-irix*)      platform=IRIX ;;
        *-*-aix*)       platform=AIX
                      case "${host}" in
                         *-*-aix4.1*)   osver=AIX41;;
                         *-*-aix4.2*)   osver=AIX42;;
                         *-*-aix4.3*)   osver=AIX43;;
                         *-*-aix4.*)    osver=AIX43;;
                      esac;;
        *-sequent-*)    platform=PTX ;;
        *-*-hp*)        platform=HP_UX ;
                        case "${host}" in
                            *-*-hpux11*)  osver=HPUX11;;
                            *-*-hpux10*)  osver=HPUX10;;
                            *)            osver=HPUX11;;
                        esac;;
        *-*-mvs*)       platform=OS390 ;;
        *-*-os400*)     platform=OS400 ;;
        *-*-OS400*)     platform=OS400 ;;
        *-*-osf*)   platform=TRU64 ;;
        *-apple-*)  platform=MACOSX ;;
    *-nto-qnx)  platform=QNX
            SAMPLE_EXTRA_LIBS="-lsocket"
            ;;
        *)              platform=UNKNOWN ;;
esac

AC_SUBST(SAMPLE_EXTRA_LIBS)
AC_SUBST(platform)



# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h float.h limits.h netdb.h netinet/in.h stdlib.h string.h strings.h sys/ioctl.h sys/socket.h sys/time.h sys/timeb.h unistd.h openssl/ssl.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL

# Checks for library functions.
AC_CHECK_FUNCS([dup2 ftime gethostbyname gettimeofday inet_ntoa localtime_r memset select socket strchr strdup strerror strrchr strstr strtoul strtoull strtol sysinfo])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
