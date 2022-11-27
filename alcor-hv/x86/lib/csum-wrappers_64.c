#include <asm/checksum.h>
#include <linux/export.h>
#include <linux/uaccess.h>
#include <asm/smap.h>

__wsum
csum_and_copy_from_user(const void __user *src, void *dst, int len)
{
	__wsum sum;

	might_sleep();
	if (!user_access_begin(src, len))
		return 0;
	sum = csum_partial_copy_generic((__force const void *)src, dst, len);
	user_access_end();
	return sum;
}

__wsum
csum_and_copy_to_user(const void *src, void __user *dst, int len)
{
	__wsum sum;

	might_sleep();
	if (!user_access_begin(dst, len))
		return 0;
	sum = csum_partial_copy_generic(src, (void __force *)dst, len);
	user_access_end();
	return sum;
}

__wsum
csum_partial_copy_nocheck(const void *src, void *dst, int len)
{
	return csum_partial_copy_generic(src, dst, len);
}
EXPORT_SYMBOL(csum_partial_copy_nocheck);

__sum16 csum_ipv6_magic(const struct in6_addr *saddr,
			const struct in6_addr *daddr,
			__u32 len, __u8 proto, __wsum sum)
{
	__u64 rest, sum64;

	rest = (__force __u64)htonl(len) + (__force __u64)htons(proto) +
		(__force __u64)sum;

	asm("	addq (%[saddr]),%[sum]\n"
	    "	adcq 8(%[saddr]),%[sum]\n"
	    "	adcq (%[daddr]),%[sum]\n"
	    "	adcq 8(%[daddr]),%[sum]\n"
	    "	adcq $0,%[sum]\n"

	    : [sum] "=r" (sum64)
	    : "[sum]" (rest), [saddr] "r" (saddr), [daddr] "r" (daddr));

	return csum_fold(
	       (__force __wsum)add32_with_carry(sum64 & 0xffffffff, sum64>>32));
}
EXPORT_SYMBOL(csum_ipv6_magic);
