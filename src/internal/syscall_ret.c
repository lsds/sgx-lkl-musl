#include <errno.h>
#include "syscall.h"

long __syscall_ret(unsigned long r)
{
        /* the errno value is extracted outside of enclave */
	return r;
}
