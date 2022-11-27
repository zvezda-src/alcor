#ifndef _ASM_X86_HUGETLB_H
#define _ASM_X86_HUGETLB_H

#include <asm/page.h>
#include <asm-generic/hugetlb.h>

#define hugepages_supported() boot_cpu_has(X86_FEATURE_PSE)

#endif /* _ASM_X86_HUGETLB_H */
