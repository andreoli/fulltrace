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

int main (int argc, char **argv)
{
	if (argc < 1)
		exit(-1);

	if (fork() > 0) {
		int fd_pid, fd_mrk;
		char line[64];
		char pid[64];
		int s, ret;

		fd_pid = open(tracing_file("set_ftrace_pid"), O_WRONLY);
		s = sprintf(pid, "%d\n", getpid());
		ret = write(fd_pid, pid, s);
		if (ret == -1) {
			printf("error!\n");
			exit(1);
		}
		close(fd_pid);

		fd_mrk = open(tracing_file("trace_marker"), O_WRONLY);
		s = sprintf(line, "----------- PROCESS START -----------\n");
		ret = write(fd_mrk, line, s);
		if (ret == -1) {
			printf("error!\n");
			exit(1);
		}
		close(fd_mrk);

		execvp(argv[1], argv+1);
	}

	return 0;
}
