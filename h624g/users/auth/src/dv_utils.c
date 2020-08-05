#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include <libytool.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


void dv_resolver_init(void)
{
	mkdir("/tmp/rad_name", 0666);
	mkdir("/tmp/rad_name/c", 0666);
	system("rm -f /tmp/rad_name/c/*");  // clear cache
}

// dv_resolver_exec: 
//   returns pid for dns query starting
//   returns 0 for dns in cache
pid_t dv_resolver_exec(char *name)
{
	pid_t pid;
	char str[80];

	sprintf(str, "/tmp/rad_name/c/r_%s", name);

	// check if name already in cache
	if (access(str, R_OK)==0) {
		//printf("resolver_exec[%s]:cached!!!\n", name);
		return 0;
	}

	pid = fork();
	if (pid==0) {
		int fd;
		fd = open(str, O_WRONLY|O_CREAT);
		if (fd < 0)
			exit(0);

		//printf("child for %s-----------\n", name);
		close(1);
		dup(fd);
		close(fd);
		execlp("/usr/sbin/aprovis", "aprovis", name, NULL);
		fprintf(stderr, "child error\n");
		exit(0);
	}
	//printf("child created %s-- %d ---------\n", name, pid);
	return pid;
}

void save_results(char *prefix, char *res, char *dst)
{
	char str[80];
	int i=0;
	char ip_str[40];
	unsigned int ip;


	if (res == NULL) {
		goto err_0;
	}


	sprintf(str, "/tmp/rad_name/c/r_%s", res);

	i = yfcat(str, "%*[^\n] %s", ip_str);
	if (i!=1) {
		goto err_0;
	}
	ydespaces(ip_str);

	ip = inet_addr(ip_str);
	if (ip==0) {
		goto err_0;
	}

	sprintf(str, "/tmp/rad_name/%s_%s", prefix, dst);
	i = yfecho(str, O_WRONLY|O_CREAT|O_TRUNC, 0644, "%s", ip_str);
	return;

err_0:
	//if (res) printf("%s(): %s result error\n", __FUNCTION__, res);
	sprintf(str, "/tmp/rad_name/%s_%s", prefix, dst);
	unlink(str);
}

int get_addr_from_file(char *prefix, char *name, char *ip_str, int ip_str_len)
{
	char fname[40];
	char str[80];
	int i;
	unsigned int ip;

	sprintf(fname, "/tmp/rad_name/%s_%s", prefix, name);

	i = yfcat(fname, "%s", str);

	if (i!=1) {
		return -1;
	}

	ydespaces(str);

	ip = inet_addr(str);

	if (ip==0) {
		return -2;
	}

	strncpy(ip_str, str, ip_str_len);

	return 0;
}

