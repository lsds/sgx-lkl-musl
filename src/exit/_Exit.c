#include <stdlib.h>
#include "syscall.h"

#ifdef SGXLKL_HW
extern void* get_exit_address();
#endif

_Noreturn void _Exit(int ec)
{
#ifdef SGXLKL_HW
	exit_enclave(SGXLKL_EXIT_TERMINATE, ec, get_exit_address(), UNUSED);	
#else
	__syscall(SYS_exit_group, ec);
	for (;;) __syscall(SYS_exit, ec);
#endif
}
