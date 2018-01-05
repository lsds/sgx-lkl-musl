static inline struct schedctx *__scheduler_self()
{
	struct schedctx *self;
	__asm__ __volatile__ ("mov %%fs:0,%0" : "=r" (self) );
	return self;
}

#define TP_ADJ(p) (p)

#define MC_PC gregs[REG_RIP]
