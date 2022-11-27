#ifndef _ASM_X86_UACCESS_64_H
#define _ASM_X86_UACCESS_64_H

#include <linux/compiler.h>
#include <linux/lockdep.h>
#include <linux/kasan-checks.h>
#include <asm/alternative.h>
#include <asm/cpufeatures.h>
#include <asm/page.h>


__must_check unsigned long
copy_user_enhanced_fast_string(void *to, const void *from, unsigned len);
__must_check unsigned long
copy_user_generic_string(void *to, const void *from, unsigned len);
__must_check unsigned long
copy_user_generic_unrolled(void *to, const void *from, unsigned len);

static __always_inline __must_check unsigned long
copy_user_generic(void *to, const void *from, unsigned len)
{
	unsigned ret;

	/*
	alternative_call_2(copy_user_generic_unrolled,
			 copy_user_generic_string,
			 X86_FEATURE_REP_GOOD,
			 copy_user_enhanced_fast_string,
			 X86_FEATURE_ERMS,
			 ASM_OUTPUT2("=a" (ret), "=D" (to), "=S" (from),
				     "=d" (len)),
			 "1" (to), "2" (from), "3" (len)
			 : "memory", "rcx", "r8", "r9", "r10", "r11");
	return ret;
}

static __always_inline __must_check unsigned long
raw_copy_from_user(void *dst, const void __user *src, unsigned long size)
{
	return copy_user_generic(dst, (__force void *)src, size);
}

static __always_inline __must_check unsigned long
raw_copy_to_user(void __user *dst, const void *src, unsigned long size)
{
	return copy_user_generic((__force void *)dst, src, size);
}

extern long __copy_user_nocache(void *dst, const void __user *src,
				unsigned size, int zerorest);

extern long __copy_user_flushcache(void *dst, const void __user *src, unsigned size);
extern void memcpy_page_flushcache(char *to, struct page *page, size_t offset,
			   size_t len);

static inline int
__copy_from_user_inatomic_nocache(void *dst, const void __user *src,
				  unsigned size)
{
	kasan_check_write(dst, size);
	return __copy_user_nocache(dst, src, size, 0);
}

static inline int
__copy_from_user_flushcache(void *dst, const void __user *src, unsigned size)
{
	kasan_check_write(dst, size);
	return __copy_user_flushcache(dst, src, size);
}
#endif /* _ASM_X86_UACCESS_64_H */
