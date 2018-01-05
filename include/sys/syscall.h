#ifdef WANT_REAL_ARCH_SYSCALLS

#ifdef _LKL_BITS_SYSCALL_H
#error "sys/syscall.h included for ARCH numbers, but LKL numbers already loaded"
#endif

#ifndef _ARCH_BITS_SYSCALL_H
#define _ARCH_BITS_SYSCALL_H
#define __INCLUDE_FROM_SYS_SYSCALL_H
#include <bits/syscall.h>
#undef __INCLUDE_FROM_SYS_SYSCALL_H
#endif

#else

#ifdef _ARCH_BITS_SYSCALL_H
#error "sys/syscall.h included for LKL numbers, but ARCH numbers already loaded"
#endif

#ifndef _LKL_BITS_SYSCALL_H
#define _LKL_BITS_SYSCALL_H
#define __INCLUDE_FROM_SYS_SYSCALL_H
#include <lkl/bits.h>
#undef  __INCLUDE_FROM_SYS_SYSCALL_H
#endif

#endif
