#include <stdlib.h>
#include "syscall.h"

#ifdef SGXLKL_HW
extern void* get_exit_address();
#else
extern void (*sim_exit_handler) (int);
#endif

_Noreturn void _Exit(int ec)
{
#ifdef SGXLKL_HW
	for (;;) exit_enclave(SGXLKL_EXIT_TERMINATE, ec, get_exit_address(), UNUSED);
#else
	sim_exit_handler(ec);
	pthread_exit(0);
#endif
}
