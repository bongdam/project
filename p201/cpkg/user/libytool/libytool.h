#ifndef __LIBYTOOL_H_
#define __LIBYTOOL_H_

#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>

#ifdef __cplusplus
extern "C" {
#endif

/*!

  @param
  @return
 */
time_t ygettime(struct timespec *ts);

/*!
  eleminate leading and trailing character in exclude
  @param	s	string pointer to be altered
  @param	exclude	the set of characters to be eliminated
  @return	pointer to string passed by parameter
 */
char *ystrtrim(char *s, const char *exclude);

/*!
  eleminate leading and trailing whitespace
  @param	s	string pointer to be altered
  @return	pointer to string passed by parameter
 */
char *ydespaces(char *s);

/*!
  Analog of vsprintf, except that it will allocate a string if *strp is
  too small to hold the output including the terminating null byte,
  and return the number of characters which have been written into *strp.
  @param	strp	pointer to buffer offered by caller to contain formatted string
  @param	buflen	size of buffer
  @param	fmt	format string that specifies how subsequent
  			arguments are converted for output
  @param	ap	va_list type for iterating arguments
  @return	int	length of formatted string.
 */
int yvasnprintf(char **strp, size_t buflen, const char *fmt, va_list ap);
int yasnprintf(char **strp, size_t buflen, const char *fmt, ...);

/*!
  Analog of vsprintf, except that it will allocate a string if buf is
  too small to hold the output including the terminating null byte,
  and return a pointer. return buf pointer if enough.
  @param	buf	buffer offered by caller to contain formatted string
  @param	buflen	size of buffer
  @param	fmt	format string that specifies how subsequent
  			arguments are converted for output
  @param	ap	va_list type for iterating arguments
  @return	buf or a new string pointer.
 */
char *yvasprintf(char *buf, size_t buflen, const char *fmt, va_list ap);

/*!
  Delimit string passed with symbols in the string delim
  @param	line	string to be delimitted
  @param	ag	array for containing tokens delimited
  @param	agsz	size of array
  @param	delim	gathering of characters by which string delimited
  @param	empty	zero-length token included if true
  @return	number of elements in array
 */
int ystrargs(char *line, char *ag[], unsigned agsz, const char *delim, int empty);

/*!
  Print formatted string to file
  @param	pathname	file name for creating or appending
  @param	flags	same as flags of open(2)
  @param	mode	access specifier of user/group/other
  @param	fmt	format string specifing how to convert arguments
  @return	number of bytes written
 */
int yfecho(const char *pathname, int flags, mode_t mode, const char *fmt, ...);

/*!
  Formatted input from file
  @param	pathname	existing file name
  @param	fmt	format string specifing how to convert arguments
  @return	number of conversion occurred succefully
 */
int yfcat(const char *pathname, const char *fmt, ...);

/*!
  Delimiting command-line string
  @param	sp	command-line string
  @param	argcp	sets the number of token splitted
  @return	array pointer containing tokens
 */
char **ybuildargv(char *sp, int *argcp);

/*!
  Concatenates NULL-terminated list of arguments into a single commmand and executes it
  @param	argv	argument list
  @param	path	could be NULL, ">output", or ">>output"
  @param	timeout	seconds to wait before timing out or 0 for no timeout
  @param	ppid	NULL to wait for child termination or pointer to pid
  @return	value of executed command or errno
 */
int yexecv(char *const argv[], char *path, int timeout, int *ppid);

/*!
  Execute formatted command-line
  @param	pathname	could be NULL, ">output", or ">>output"
  @param	arg	format string specifing how to convert arguments
  @return	value of executed command or errno
 */
int yexecl(char *pathname, const char *arg, ...);

/*!
  Run in the background
  @param	nochdir
  @param	noclose
  @return	0 on sucess, otherwise -1 and sets errno
 */
int ydaemon(int nochdir, int noclose, const char *fmt, ...);

#ifdef __cplusplus
}
#endif

#define yecho(f, arg...) yfecho(f, O_WRONLY | O_CREAT | O_TRUNC, 0644, arg)

static inline int ystrlen_zero(const char *s)
{
	return (!s || (*s == '\0'));
}

#define _countof(x) (sizeof(x) / sizeof((x)[0]))

/*!
  close all FDs from given lowfd
  @param	lowfd start fd to be closed from
  @return	none
 */
void yclosefrom(int lowfd);

static inline int ywrite_pid(const char *pathname)
{
	return yecho(pathname, "%d\n", getpid());
}

static inline int ytest_pid(const char *pathname)
{
	int pid;

	if (yfcat(pathname, "%d", &pid) != 1 || pid <= 0)
		return 0;
	return (kill(pid, 0)) ? 0 : pid;
}
#endif /* __LIBYTOOL_H_ */
