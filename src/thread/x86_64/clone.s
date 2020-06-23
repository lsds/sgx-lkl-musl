.text
.global __clone
.hidden __clone
.type   __clone,@function
// int __clone(int (*func)(void *), void *stack, int flags, void *arg, pid_t *ptid, void *newtls, pid_t *ctid)
// %rdi = func
// %rsi = stack
// %rdx = flags
// %rcx = arg
// %r8  = ptid
// %r9  = newtls
// 8(%rsp) = ctid
__clone:
	// Push the function and argument onto the new stack:
	sub  $16, %rsi
	mov  %rcx, (%rsi)
	mov  %rdi, 8(%rsi)
	// Load the ctid argument before we start modifying the stack.
	mov 8(%rsp),%r10
	// Store the arguments in a six-element array in syscall argument order.
	// The last element is unused.  We also need to keep the stack 16-byte
	// aligned, so push r9 twice more for padding.
	push %r9
	push %r9
	push %r9
	push %r10
	push %r8
	push %rsi
	push %rdx
	// %rsp is now the start of an array containing
	// {flags, stack, ptid, ctid, newtls}.  Store it in the second argument
	// register.
	mov  %rsp, %rsi
	# LKL's clone system call number in arg 1
	mov  $220, %rdi
	call lkl_syscall@PLT
	test %eax,%eax
	jnz 1f
	# End of stack hint
	xor %ebp,%ebp
	pop %rdi
	pop %r9
	and $-16,%rsp
	call *%r9
	// exit system call if this function returns
	subq $5*8, %rsp
	push %rax
	mov %rsp, %rsi
	mov $93, %rdi
	call lkl_syscall@PLT
	// Should be unreachable, trap if it is reached
	ud2
1:	add $7*8, %rsp
	ret

	.weak lkl_syscall
