#define _GNU_SOURCE
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>

#include "pthread_impl.h"

int pthread_setname_np(pthread_t thread, const char *name)
{
	lthread_set_funcname(thread, name);
	return 0;
}
