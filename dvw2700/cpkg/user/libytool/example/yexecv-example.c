#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "../libytool.h"

#define yeval(cmd, args...) ({ \
	char *argv[] = { cmd , ## args, NULL }; \
	yexecv(argv, ">/dev/console", 0, NULL); \
})

int main(void)
{
	{
		char *argv[] = { "echo", "-e", "Hello World!", NULL };
		yexecv(argv, NULL, 0, NULL);
	}

	{
		char *argv[] = { "cat", NULL };
		int status;

		dprintf(STDOUT_FILENO, "Press ^D to exit: ");

		status = yexecv(argv, NULL, 5, NULL);
		if (status < 0)
			perror(argv[0]);
		else if (WIFEXITED(status))
			printf("exited with %d code\n", WEXITSTATUS(status));
		else if (WIFSIGNALED(status))
			printf("killed by signal %d\n", WTERMSIG(status));
		else if (WIFSTOPPED(status))
			printf("stopped by signal %d\n", WSTOPSIG(status));
		else if (WIFCONTINUED(status))
			printf("continued\n");
	}
	{
		char *argv[] = { "cat", "/proc/sys/kernel/printk", NULL };
		int child = 0;
		int status;

		yexecv(argv, NULL, 0, &child);
		if (child > 0)
			waitpid(child, &status, 0);
	}
	yeval("sh", "-c", "ntpclient &");

	return 0;
}
