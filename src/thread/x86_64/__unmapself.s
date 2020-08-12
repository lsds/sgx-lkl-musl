/* Copyright 2011-2012 Nicholas J. Kain, licensed under standard MIT license */
.text
.global __unmapself
.type   __unmapself,@function
__unmapself:
	subq $5*8, %rsp
	push %rsi
	push %rdi
	mov %rsp, %rsi
	mov $215,%rdi   /* LKL's SYS_munmap */
	call lkl_syscall@PLT         /* munmap(arg2,arg3) */
	// exit system call if this function returns
	subq $5*8, %rsp
	xor %rax, %rax /* exit() args: always return success */
	push %rax
	mov %rsp, %rsi
	mov $93, %rdi
	call lkl_syscall@PLT
	// Should be unreachable, trap if it is reached
	ud2

	.weak lkl_syscall
