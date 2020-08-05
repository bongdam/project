#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <fcntl.h>
#include <dirent.h>
#include "shutils.h"

#define PSCSCAN_CMDLINE	1

typedef struct {
	int pid;
	char comm[16];
	char *cmdline;
} procps_comm_t;

static int
read_to_buffer(const char *filename, void *buf, ssize_t bsize)
{
	int fd;
	/* open_read_close() would do two reads, checking for EOF.
	 * When you have 10000 /proc/$NUM/stat to read, it isn't desirable */
	ssize_t ret = -1;
	fd = open(filename, O_RDONLY);
	if (fd >= 0) {
		ret = read(fd, buf, bsize - 2);
		close(fd);
	}
	((char *)buf)[ret > 0 ? ret : 0] = '\0';
	return ret;
}

static void
procps_comm_free(procps_comm_t *p)
{
	procps_comm_t *tmp;

	for (tmp = p; p && tmp->pid > 0; tmp++)
		if (tmp->cmdline)
			free(tmp->cmdline);
	if (p)
		free(p);
}

static procps_comm_t *
procps_comm_scan(unsigned flags)
{
	DIR *dir;
	struct dirent *entry;
	char buf[1024];
	char comm[16];
	char filename[sizeof("/proc//cmdline") + sizeof(int) * 3];
	int pid;
	char *cp;
	int n, pos = 0, pcsize = 2;
	procps_comm_t *p = NULL;

	dir = opendir("/proc");
	if (!dir)
		return NULL;

	while ((entry = readdir(dir)) != NULL) {
		if (strspn(entry->d_name, "0123456789") != strlen(entry->d_name))
			continue;
		pid = strtol(entry->d_name, NULL, 10);
		sprintf(filename, "/proc/%d/stat", pid);
		n = read_to_buffer(filename, buf, sizeof(buf));
		if (n <= 0)
			continue;
		cp = strrchr(buf, ')');
		cp[0] = '\0';
		cp = strchr(buf, '(');
		memcpy(comm, cp + 1, sizeof(comm) - 1);
		comm[sizeof(comm) - 1] = '\0';

		if (p == NULL || ((pos + 2) > pcsize)) {
			procps_comm_t *nps;

			pcsize <<= 1;
			nps = realloc(p, sizeof(procps_comm_t) * pcsize);
			if (nps == NULL)
				goto oom;
			p = nps;
		}
		p[pos].pid = pid;
		strncpy(p[pos].comm, comm, sizeof(p[0].comm));
		p[pos].cmdline = NULL;
		if (flags & PSCSCAN_CMDLINE) {
			sprintf(filename, "/proc/%d/cmdline", pid);
			n = read_to_buffer(filename, buf, sizeof(buf));
			if (n > 0) {
				p[pos].cmdline = calloc(n + 2, sizeof(char));
				if (p[pos].cmdline)
					memcpy(p[pos].cmdline, buf, n + 1);
			}
		}
		++pos;
	}
	closedir(dir);

	if (p)
		p[pos].pid = 0;

	return p;
 oom:
	procps_comm_free(p);
	return NULL;
}

static int
comm_matched(procps_comm_t *p, const char *procName)
{
	int argv1idx;

	/* comm does not match */
	if (strncmp(p->comm, procName, 15) != 0)
		return 0;

	/* in Linux, if comm is 15 chars, it may be a truncated */
	if (p->comm[14] == '\0')	/* comm is not truncated - match */
		return 1;

	/* comm is truncated, but first 15 chars match.
	 * This can be crazily_long_script_name.sh!
	 * The telltale sign is base_name(argv[1]) == procName. */

	if (!p->cmdline)
		return 0;

	argv1idx = strlen(p->cmdline) + 1;
	if (p->cmdline[argv1idx] == '\0')
		return 0;

	if (strcmp(base_name(p->cmdline + argv1idx), procName) != 0)
		return 0;

	return 1;
}

int getpidbyname(const char *command, pid_t **ppid)
{
	procps_comm_t *p, *ps;
	size_t num_array, num_pid = 0;

	if (command == NULL || command[0] == '\0' || ppid == NULL)
		return 0;

	*ppid = NULL;
	ps = procps_comm_scan((strlen(command) > 14) ? PSCSCAN_CMDLINE : 0);
	if (ps) {
		num_array = 0;
		for (p = ps; p->pid > 0; p++) {
			if (comm_matched(p, command)
			    || (p->cmdline && !strcmp(base_name(p->cmdline), command))) {
			    	if (num_array <= num_pid) {
			    		num_array = num_pid + 10;
					*ppid = realloc(*ppid, sizeof(pid_t) * num_array);
				}
				(*ppid)[num_pid++] = p->pid;
			}
		}
		procps_comm_free(ps);
	}

	return num_pid;
}
