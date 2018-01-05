#include "locale_impl.h"
#include "lthread_int.h"
#include <lthread.h>
#include "libc.h"

locale_t __uselocale(locale_t new)
{
        struct lthread *self = lthread_self();
	locale_t old = self->locale;
	locale_t global = &libc.global_locale;

	if (new) self->locale = new == LC_GLOBAL_LOCALE ? global : new;

	return old == global ? LC_GLOBAL_LOCALE : old;
}

weak_alias(__uselocale, uselocale);
