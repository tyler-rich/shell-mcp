// cpushim: a test-only LD_PRELOAD library for TestGitThreadsIndependentOfCPUs
// (handoff N-30). Never shipped. It makes sysconf(_SC_NPROCESSORS_ONLN) and
// _SC_NPROCESSORS_CONF answer CPUSHIM_CPUS, which is what git's
// online_cpus() reads on Linux (thread-utils.c, git 2.55; CPU affinity does
// not change it), and appends one line, the process's command name, to the
// file CPUSHIM_LOG for every thread the process starts with pthread_create.
#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

long sysconf(int name) {
	static long (*real)(int);
	if (!real)
		real = (long (*)(int))dlsym(RTLD_NEXT, "sysconf");
	if (name == _SC_NPROCESSORS_ONLN || name == _SC_NPROCESSORS_CONF) {
		const char *v = getenv("CPUSHIM_CPUS");
		if (v && *v)
			return atol(v);
	}
	return real(name);
}

int pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start)(void *), void *arg) {
	static int (*real)(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *);
	if (!real)
		real = (int (*)(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *))dlsym(RTLD_NEXT, "pthread_create");
	const char *log = getenv("CPUSHIM_LOG");
	if (log && *log) {
		int fd = open(log, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0600);
		if (fd >= 0) {
			char comm[64] = {0};
			int cf = open("/proc/self/comm", O_RDONLY | O_CLOEXEC);
			if (cf >= 0) {
				ssize_t n = read(cf, comm, sizeof(comm) - 1);
				close(cf);
				if (n <= 0)
					strcpy(comm, "?\n");
			}
			ssize_t ignored = write(fd, comm, strlen(comm));
			(void)ignored;
			close(fd);
		}
	}
	return real(thread, attr, start, arg);
}
