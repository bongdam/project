#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <limits.h>

void yclosefrom(int lowfd)
{
	int fd, nfd, fd_size = 32;
	int *p = NULL;
	char path[PATH_MAX], *endp;
	struct dirent *dent;
	DIR *dirp;

	nfd = 0;
	/* check for a /proc/\d+/fd directory. */
	snprintf(path, sizeof(path), "/proc/%u/fd", getpid());
	if ((dirp = opendir(path))) {
		while ((dent = readdir(dirp)) != NULL) {
			fd = (int)strtol(dent->d_name, &endp, 10);
			if (dent->d_name != endp && *endp == '\0' &&
			    fd >= 0 && fd < INT_MAX &&
			    fd >= lowfd && fd != dirfd(dirp)) {
				if (!nfd || nfd >= fd_size) {
					fd_size <<= 1;
					p = realloc(p, fd_size * sizeof(int));
					if (!p)
						break;
				}
				p[nfd++] = fd;
			}
		}
		closedir(dirp);
	}

	if (p) {
		while (--nfd >= 0)
			(void)close(p[nfd]);
		free(p);
	}
}
