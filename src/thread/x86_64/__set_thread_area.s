/* Copyright 2011-2012 Nicholas J. Kain, licensed under standard MIT license */
.text
.global __set_thread_area
.hidden __set_thread_area
.type __set_thread_area,@function
__set_thread_area:
	subq $4*8, %rsp
	push %rdi
	push $0x1002            /* SET_FS register */
	mov $167, %rdi          /* LKL's SYS_prctl */
	call lkl_syscall@PLT    /* arch_prctl(SET_FS, arg)*/
	add $6*8, %rsp
	ret

	.weak lkl_syscall