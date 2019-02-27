#include "sgx_enclave_config.h"

#ifdef SGXLKL_HW
void __sgx_lkl_entry(uint64_t call_id, void* arg);

__asm__(
/* TODO: this should go to a linker script */
".section .note.sigstruct\n"
".space 1808\n"

".section .note.token\n"
".space 304\n"

".section .text\n"
".globl entry\n"
".type entry, @function\n"
"entry:\n"
/* on entry, rax - tcs.cssa, rbx - TCS addr, rcx - address of instruction following eenter
 * fs:0 - self pointer
 * fs:8 - offset of tcs from enclave base / 0x1 if initialized
 * fs:16 - offset of enclave_parms from enclave base
 * fs:48 - offset of tls from enclave base
 */

//TODO: we need to verify if the ecall is a legit one
/* exit if cssa > 0 and call id is not SGXLKL_ENTER_HANDLE_SIGNAL */
//"   cmp %rax,$0\n"
//"   je __initialize\n"
//"   cmp %rdi,$1\n"
//"   jne __unexpected_call\n"

"__initialize: \n"
/* enclave parms in %rax */
"   movq %fs:16,%rax\n"
"   cmp $0x1,%fs:8\n"
"   je _thread_initialized\n"
/* enclave base address in %rbx */
"   subq %fs:8,%rbx\n"
/* store self pointer at %fs:0 */
"   addq %rbx,%fs:0\n"
/* address of tls */
"   addq %rbx,%fs:48\n"
/* address of enclave parms structure */
"   addq %rbx,%fs:16\n"
"   addq %rbx,%rax\n"
/* base */
"   movq %rbx,(%rax)\n"
/* heap */
"   addq %rbx,8(%rax)\n"
/* stack */
"   addq %rbx,16(%rax)\n"
/* ossa */
"   addq %rbx,24(%rax)\n"
"   movq $0x1,%fs:8\n"
/* save exit address */
"   movq %rcx,48(%rax)\n"
/* save external rsp and rbp */
"   movq %rsp,56(%rax)\n"
"   movq %rbp,64(%rax)\n"
"   movq 16(%rax),%rsp\n"
"   movq 16(%rax),%rbp\n"
"   jmp __sgx_lkl_entry\n"

"_thread_initialized: \n"
/* SGXLKL_ENTER_HANDLE_SIGNAL: rdi == 2 */
"   cmp $2, %rdi\n"
"   je .Signal\n"
"   jmp __resume\n"


".Signal:"
/* prepare for signal handling */
/* save exit address */
"   movq %rcx,136(%rax)\n"
/* save external rsp and rbp */
"   movq %rsp,144(%rax)\n"
"   movq %rbp,152(%rax)\n"
/* put tcs address in rdi */
"   movq %rbx,%rdi\n"
/* start of ssa: tcs - 0x3000 */
/* start of gpr: ssa start + 4096 - 184 */
"   subq $0x20b8,%rdi\n"

/* get rsp and rbp from ssa */
"   movq 32(%rdi),%rsp\n"
"   movq 40(%rdi),%rbp\n"
"   subq $0x1000,%rsp\n"
"   subq $0x1000,%rbp\n"
"   jmp __enclave_signal_handler\n"


"__resume:\n"
/* are we doing signal handling? */
/* enclave_parms->eh_handling: rbx == 1 */
"   movq 160(%rax),%rbx\n"
"   cmp $1, %rbx\n"
"   je __restore_regs\n"
/* check thread status - must be OUTSIDE */
"   movq 120(%rax),%rbx\n"
"   cmp $1, %rbx\n"
"   jne __unexpected_call\n"
/* save exit address */
"   movq %rcx,48(%rax)\n"
/* save external rsp and rbp */
"   movq %rsp,56(%rax)\n"
"   movq %rbp,64(%rax)\n"

"__restore_regs:\n"
"   movq %rax, %rdi\n"
"   addq $168, %rdi\n"
"   movq $1, %rsi\n"
/* longjmp implementation */
"	mov %rsi,%rax\n"           /* val will be longjmp return */
"	test %rax,%rax\n"
"	jnz 1f\n"
"	inc %rax\n"                /* if val==0, val=1 per longjmp semantics */
"1:\n"
"	mov (%rdi),%rbx\n"         /* rdi is the jmp_buf, restore regs from it */
"	mov 8(%rdi),%rbp\n"
"	mov 16(%rdi),%r12\n"
"	mov 24(%rdi),%r13\n"
"	mov 32(%rdi),%r14\n"
"	mov 40(%rdi),%r15\n"
"	mov 48(%rdi),%rdx\n"       /* this ends up being the stack pointer */
"	mov %rdx,%rsp\n"
"	mov 56(%rdi),%rdx\n"       /* this is the instruction pointer */
"	jmp *%rdx\n"               /* goto saved address without altering rsp */

"__unexpected_call: \n"
"   movq $3,%rdi\n"
"   movq $4,%rsi\n"
"   movq %rcx,%rbx\n"
"   movq $4,%rax\n"
"   .byte 0x0f \n"
"   .byte 0x01 \n"
"   .byte 0xd7 \n"
);

#else /* !SGXLKL_HW */
int __libc_init_enclave(int argc, char **argv, enclave_config_t* encl);

void __sgx_init_enclave(enclave_config_t* encl)
{
    /* Copy pointer to host OS-created pthread struct
     * from fs:0 t fs:48 which will serve as a placeholder
     * until we have initialised the scheduling context
     * (see init_tls in src/env/__init_tls.c).
     *
     * fs:0 will be a (self) pointer to the beginning of the
     * thread control block, fs:48 points to the scheduling
     * context */
    __asm__ volatile ( "movq %%fs:0,%%rax;\n\t"
                       "movq %%rax,%%fs:48;\n\t"
                      ::: "%rax" );
    __libc_init_enclave(encl->argc, encl->argv, encl);
}
 
#endif /* SGXLKL_HW */
