 
#include <linux/compiler.h>
#include <linux/export.h>
#include <asm/checksum.h>
#include <asm/word-at-a-time.h>

static inline unsigned short from32to16(unsigned a) 
{
	unsigned short b = a >> 16; 
	asm("addw %w2,%w0\n\t"
	    "adcw $0,%w0\n" 
	    : "=r" (b)
	    : "0" (b), "r" (a));
	return b;
}

__wsum csum_partial(const void *buff, int len, __wsum sum)
{
	u64 temp64 = (__force u64)sum;
	unsigned odd, result;

	odd = 1 & (unsigned long) buff;
	if (unlikely(odd)) {
		if (unlikely(len == 0))
			return sum;
		temp64 = ror32((__force u32)sum, 8);
		temp64 += (*(unsigned char *)buff << 8);
		len--;
		buff++;
	}

	while (unlikely(len >= 64)) {
		asm("addq 0*8(%[src]),%[res]\n\t"
		    "adcq 1*8(%[src]),%[res]\n\t"
		    "adcq 2*8(%[src]),%[res]\n\t"
		    "adcq 3*8(%[src]),%[res]\n\t"
		    "adcq 4*8(%[src]),%[res]\n\t"
		    "adcq 5*8(%[src]),%[res]\n\t"
		    "adcq 6*8(%[src]),%[res]\n\t"
		    "adcq 7*8(%[src]),%[res]\n\t"
		    "adcq $0,%[res]"
		    : [res] "+r" (temp64)
		    : [src] "r" (buff)
		    : "memory");
		buff += 64;
		len -= 64;
	}

	if (len & 32) {
		asm("addq 0*8(%[src]),%[res]\n\t"
		    "adcq 1*8(%[src]),%[res]\n\t"
		    "adcq 2*8(%[src]),%[res]\n\t"
		    "adcq 3*8(%[src]),%[res]\n\t"
		    "adcq $0,%[res]"
			: [res] "+r" (temp64)
			: [src] "r" (buff)
			: "memory");
		buff += 32;
	}
	if (len & 16) {
		asm("addq 0*8(%[src]),%[res]\n\t"
		    "adcq 1*8(%[src]),%[res]\n\t"
		    "adcq $0,%[res]"
			: [res] "+r" (temp64)
			: [src] "r" (buff)
			: "memory");
		buff += 16;
	}
	if (len & 8) {
		asm("addq 0*8(%[src]),%[res]\n\t"
		    "adcq $0,%[res]"
			: [res] "+r" (temp64)
			: [src] "r" (buff)
			: "memory");
		buff += 8;
	}
	if (len & 7) {
		unsigned int shift = (8 - (len & 7)) * 8;
		unsigned long trail;

		trail = (load_unaligned_zeropad(buff) << shift) >> shift;

		asm("addq %[trail],%[res]\n\t"
		    "adcq $0,%[res]"
			: [res] "+r" (temp64)
			: [trail] "r" (trail));
	}
	result = add32_with_carry(temp64 >> 32, temp64 & 0xffffffff);
	if (unlikely(odd)) {
		result = from32to16(result);
		result = ((result >> 8) & 0xff) | ((result & 0xff) << 8);
	}
	return (__force __wsum)result;
}
EXPORT_SYMBOL(csum_partial);

__sum16 ip_compute_csum(const void *buff, int len)
{
	return csum_fold(csum_partial(buff,len,0));
}
EXPORT_SYMBOL(ip_compute_csum);
