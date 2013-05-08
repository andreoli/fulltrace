#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#define _STR(x) #x
#define STR(x) _STR(x)
#define MAX_PATH 256

const char *find_debugfs(void)
{
	static char debugfs[MAX_PATH+1];
	static int debugfs_found;
	char type[100];
	FILE *fp;

	if (debugfs_found)
		return debugfs;

	if ((fp = fopen("/proc/mounts","r")) == NULL) {
		perror("/proc/mounts");
		return NULL;
	}

	while (fscanf(fp, "%*s %"
				STR(MAX_PATH)
				"s %99s %*s %*d %*d\n",
				debugfs, type) == 2) {
		if (strcmp(type, "debugfs") == 0)
			break;
	}
	fclose(fp);

	if (strcmp(type, "debugfs") != 0) {
		fprintf(stderr, "debugfs not mounted");
		return NULL;
	}

	strcat(debugfs, "/tracing/");
	debugfs_found = 1;

	return debugfs;
}

const char *tracing_file(const char *file_name)
{
	static char trace_file[MAX_PATH+1];
	snprintf(trace_file, MAX_PATH, "%s/%s", find_debugfs(), file_name);
	return trace_file;
}

void die (int fd, int exit_val)
{
	close(fd);
	exit(exit_val);
}

int main (int argc, char **argv)
{
	if (argc < 3)
		exit(-1);

	if (fork() > 0) {
		int fd_pid, fd_enabled, fd_on;
		char pid[64];
		size_t s;
		ssize_t ret;

		fd_pid = open(tracing_file("set_ftrace_pid"), O_WRONLY);
		s = sprintf(pid, "%d\n", getpid());
		ret = write(fd_pid, (void *)pid, s);
		if (ret == -1) {
			perror("write fd_pid");
			die(fd_pid, 1);
		}
		close(fd_pid);

		if(atoi(argv[1]) < 37) {
			fd_enabled = open(tracing_file("tracing_enabled"), O_WRONLY);
			ret = write(fd_enabled, (void *)"1", 1);
			if (ret == -1) {
				perror("write fd_enabled");
				die(fd_enabled, 1);
			}
			close(fd_enabled);
		}
		fd_on = open(tracing_file("tracing_on"), O_WRONLY);
		ret = write(fd_on, (void *)"1", 1);
		if (ret == -1) {
			perror("write fd_on");
			die(fd_on, 1);
		}
		close(fd_on);

		execvp(argv[2], argv+2);
	}

	return 0;
}
