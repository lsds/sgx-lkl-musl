#include <stdlib.h>
#include <signal.h>
#include "syscall.h"
#include "pthread_impl.h"
#include "atomic.h"

_Noreturn void abort(void)
{
	raise(SIGABRT);
	a_crash();
	raise(SIGKILL);
	_Exit(127);
}
