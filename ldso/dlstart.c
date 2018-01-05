#include <stddef.h>
#include "dynlink.h"
#include "enclave_config.h"

#ifndef START
#define START "_dlstart"
#endif

#define SHARED

#include "crt_arch.h"

#ifndef GETFUNCSYM
#define GETFUNCSYM(fp, sym, got) do { \
	__attribute__((__visibility__("hidden"))) void sym(); \
	static void (*static_func_ptr)() = sym; \
	__asm__ __volatile__ ( "" : "+m"(static_func_ptr) : : "memory"); \
	*(fp) = static_func_ptr; } while(0)
#endif

void* _dlstart_c(enclave_config_t *encl)
{
	size_t i, aux[AUX_CNT], dyn[DYN_CNT];
	size_t *rel, rel_size, base, *dynv, *auxv, *envp;

	auxv = encl->auxv;
        
	struct fdpic_loadseg *segs, fakeseg;
	size_t j;
	for (i=0; i<AUX_CNT; i++) aux[i] = 0;
	for (i=0; auxv[i]; i+=2) if (auxv[i]<AUX_CNT)
		aux[auxv[i]] = auxv[i+1];

#ifdef SGXLKL_HW
	base = (char*) encl->base + encl->heapsize;
#else
	base = encl->base;
#endif


	// Determine location of dynamic section of the loader. It is equal
	// to the base address + the virtual address of the dynamic section (as
	// specified in the corresponding program header).
	//
	Ehdr *eh = (void *)base;
	Phdr *ph = (void *)(base + eh->e_phoff);
	size_t phnum = eh->e_phnum;
	size_t phent = eh->e_phentsize;
	while (phnum-- && ph->p_type != PT_DYNAMIC)
		ph = (void *)((size_t)ph + phent);
	dynv = (void *)(base + ph->p_vaddr);

	for (i=0; i<DYN_CNT; i++) dyn[i] = 0;
	for (i=0; dynv[i]; i+=2) if (dynv[i]<DYN_CNT)
		dyn[dynv[i]] = dynv[i+1];

    //Temporary: Set base to 0 to compute rel/rela offsets correctly.
    //base = 0;

	rel = (void *)(base+dyn[DT_REL]);
	rel_size = dyn[DT_RELSZ];
	for (; rel_size; rel+=2, rel_size-=2*sizeof(size_t)) {
		if (!IS_RELATIVE(rel[1], 0)) continue;
		size_t *rel_addr = (void *)(base + rel[0]);
		*rel_addr += base;
	}

	rel = (void *)(base+dyn[DT_RELA]);
	rel_size = dyn[DT_RELASZ];
	for (; rel_size; rel+=3, rel_size-=3*sizeof(size_t)) {
		if (!IS_RELATIVE(rel[1], 0)) continue;
		size_t *rel_addr = (void *)(base + rel[0]);
		*rel_addr = base + rel[2];
	}

	stage2_func dls2;
	GETFUNCSYM(&dls2, __dls2, dyn[DT_PLTGOT]);
	return dls2((void *)base, encl);
}
