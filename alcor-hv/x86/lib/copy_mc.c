
#include <linux/jump_label.h>
#include <linux/uaccess.h>
#include <linux/export.h>
#include <linux/string.h>
#include <linux/types.h>

#include <asm/mce.h>

#ifdef CONFIG_X86_MCE
static DEFINE_STATIC_KEY_FALSE(copy_mc_fragile_key);

void enable_copy_mc_fragile(void)
{
	static_branch_inc(&copy_mc_fragile_key);
}
#define copy_mc_fragile_enabled (static_branch_unlikely(&copy_mc_fragile_key))

__visible notrace unsigned long
copy_mc_fragile_handle_tail(char *to, char *from, unsigned len)
{
	for (; len; --len, to++, from++)
		if (copy_mc_fragile(to, from, 1))
			break;
	return len;
}
#else
void enable_copy_mc_fragile(void)
{
}
#define copy_mc_fragile_enabled (0)
#endif

unsigned long copy_mc_enhanced_fast_string(void *dst, const void *src, unsigned len);

unsigned long __must_check copy_mc_to_kernel(void *dst, const void *src, unsigned len)
{
	if (copy_mc_fragile_enabled)
		return copy_mc_fragile(dst, src, len);
	if (static_cpu_has(X86_FEATURE_ERMS))
		return copy_mc_enhanced_fast_string(dst, src, len);
	memcpy(dst, src, len);
	return 0;
}
EXPORT_SYMBOL_GPL(copy_mc_to_kernel);

unsigned long __must_check copy_mc_to_user(void *dst, const void *src, unsigned len)
{
	unsigned long ret;

	if (copy_mc_fragile_enabled) {
		__uaccess_begin();
		ret = copy_mc_fragile(dst, src, len);
		__uaccess_end();
		return ret;
	}

	if (static_cpu_has(X86_FEATURE_ERMS)) {
		__uaccess_begin();
		ret = copy_mc_enhanced_fast_string(dst, src, len);
		__uaccess_end();
		return ret;
	}

	return copy_user_generic(dst, src, len);
}
