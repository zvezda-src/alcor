
#include <linux/uaccess.h>
#include <linux/export.h>

#include <asm/tlbflush.h>

unsigned long
copy_from_user_nmi(void *to, const void __user *from, unsigned long n)
{
	unsigned long ret;

	if (!__access_ok(from, n))
		return n;

	if (!nmi_uaccess_okay())
		return n;

	/*
	pagefault_disable();
	ret = __copy_from_user_inatomic(to, from, n);
	pagefault_enable();

	return ret;
}
EXPORT_SYMBOL_GPL(copy_from_user_nmi);
