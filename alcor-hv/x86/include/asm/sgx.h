#ifndef _ASM_X86_SGX_H
#define _ASM_X86_SGX_H

#include <linux/bits.h>
#include <linux/types.h>


#define SGX_CPUID		0x12
#define SGX_CPUID_EPC		2
#define SGX_CPUID_EPC_INVALID	0x0
#define SGX_CPUID_EPC_SECTION	0x1
#define SGX_CPUID_EPC_MASK	GENMASK(3, 0)

enum sgx_encls_function {
	ECREATE	= 0x00,
	EADD	= 0x01,
	EINIT	= 0x02,
	EREMOVE	= 0x03,
	EDGBRD	= 0x04,
	EDGBWR	= 0x05,
	EEXTEND	= 0x06,
	ELDU	= 0x08,
	EBLOCK	= 0x09,
	EPA	= 0x0A,
	EWB	= 0x0B,
	ETRACK	= 0x0C,
	EAUG	= 0x0D,
	EMODPR	= 0x0E,
	EMODT	= 0x0F,
};

#define SGX_ENCLS_FAULT_FLAG 0x40000000

enum sgx_return_code {
	SGX_EPC_PAGE_CONFLICT		= 7,
	SGX_NOT_TRACKED			= 11,
	SGX_CHILD_PRESENT		= 13,
	SGX_INVALID_EINITTOKEN		= 16,
	SGX_PAGE_NOT_MODIFIABLE		= 20,
	SGX_UNMASKED_EVENT		= 128,
};

#define SGX_MODULUS_SIZE 384

enum sgx_miscselect {
	SGX_MISC_EXINFO		= BIT(0),
};

#define SGX_MISC_RESERVED_MASK	GENMASK_ULL(63, 1)

#define SGX_SSA_GPRS_SIZE		184
#define SGX_SSA_MISC_EXINFO_SIZE	16

enum sgx_attribute {
	SGX_ATTR_INIT		= BIT(0),
	SGX_ATTR_DEBUG		= BIT(1),
	SGX_ATTR_MODE64BIT	= BIT(2),
	SGX_ATTR_PROVISIONKEY	= BIT(4),
	SGX_ATTR_EINITTOKENKEY	= BIT(5),
	SGX_ATTR_KSS		= BIT(7),
};

#define SGX_ATTR_RESERVED_MASK	(BIT_ULL(3) | BIT_ULL(6) | GENMASK_ULL(63, 8))

struct sgx_secs {
	u64 size;
	u64 base;
	u32 ssa_frame_size;
	u32 miscselect;
	u8  reserved1[24];
	u64 attributes;
	u64 xfrm;
	u32 mrenclave[8];
	u8  reserved2[32];
	u32 mrsigner[8];
	u8  reserved3[32];
	u32 config_id[16];
	u16 isv_prod_id;
	u16 isv_svn;
	u16 config_svn;
	u8  reserved4[3834];
} __packed;

enum sgx_tcs_flags {
	SGX_TCS_DBGOPTIN	= 0x01,
};

#define SGX_TCS_RESERVED_MASK	GENMASK_ULL(63, 1)
#define SGX_TCS_RESERVED_SIZE	4024

struct sgx_tcs {
	u64 state;
	u64 flags;
	u64 ssa_offset;
	u32 ssa_index;
	u32 nr_ssa_frames;
	u64 entry_offset;
	u64 exit_addr;
	u64 fs_offset;
	u64 gs_offset;
	u32 fs_limit;
	u32 gs_limit;
	u8  reserved[SGX_TCS_RESERVED_SIZE];
} __packed;

struct sgx_pageinfo {
	u64 addr;
	u64 contents;
	u64 metadata;
	u64 secs;
} __packed __aligned(32);


enum sgx_page_type {
	SGX_PAGE_TYPE_SECS,
	SGX_PAGE_TYPE_TCS,
	SGX_PAGE_TYPE_REG,
	SGX_PAGE_TYPE_VA,
	SGX_PAGE_TYPE_TRIM,
};

#define SGX_NR_PAGE_TYPES	5
#define SGX_PAGE_TYPE_MASK	GENMASK(7, 0)

enum sgx_secinfo_flags {
	SGX_SECINFO_R			= BIT(0),
	SGX_SECINFO_W			= BIT(1),
	SGX_SECINFO_X			= BIT(2),
	SGX_SECINFO_SECS		= (SGX_PAGE_TYPE_SECS << 8),
	SGX_SECINFO_TCS			= (SGX_PAGE_TYPE_TCS << 8),
	SGX_SECINFO_REG			= (SGX_PAGE_TYPE_REG << 8),
	SGX_SECINFO_VA			= (SGX_PAGE_TYPE_VA << 8),
	SGX_SECINFO_TRIM		= (SGX_PAGE_TYPE_TRIM << 8),
};

#define SGX_SECINFO_PERMISSION_MASK	GENMASK_ULL(2, 0)
#define SGX_SECINFO_PAGE_TYPE_MASK	(SGX_PAGE_TYPE_MASK << 8)
#define SGX_SECINFO_RESERVED_MASK	~(SGX_SECINFO_PERMISSION_MASK | \
					  SGX_SECINFO_PAGE_TYPE_MASK)

struct sgx_secinfo {
	u64 flags;
	u8  reserved[56];
} __packed __aligned(64);

#define SGX_PCMD_RESERVED_SIZE 40

struct sgx_pcmd {
	struct sgx_secinfo secinfo;
	u64 enclave_id;
	u8  reserved[SGX_PCMD_RESERVED_SIZE];
	u8  mac[16];
} __packed __aligned(128);

#define SGX_SIGSTRUCT_RESERVED1_SIZE 84
#define SGX_SIGSTRUCT_RESERVED2_SIZE 20
#define SGX_SIGSTRUCT_RESERVED3_SIZE 32
#define SGX_SIGSTRUCT_RESERVED4_SIZE 12

struct sgx_sigstruct_header {
	u64 header1[2];
	u32 vendor;
	u32 date;
	u64 header2[2];
	u32 swdefined;
	u8  reserved1[84];
} __packed;

struct sgx_sigstruct_body {
	u32 miscselect;
	u32 misc_mask;
	u8  reserved2[20];
	u64 attributes;
	u64 xfrm;
	u64 attributes_mask;
	u64 xfrm_mask;
	u8  mrenclave[32];
	u8  reserved3[32];
	u16 isvprodid;
	u16 isvsvn;
} __packed;

struct sgx_sigstruct {
	struct sgx_sigstruct_header header;
	u8  modulus[SGX_MODULUS_SIZE];
	u32 exponent;
	u8  signature[SGX_MODULUS_SIZE];
	struct sgx_sigstruct_body body;
	u8  reserved4[12];
	u8  q1[SGX_MODULUS_SIZE];
	u8  q2[SGX_MODULUS_SIZE];
} __packed;

#define SGX_LAUNCH_TOKEN_SIZE 304


#ifdef CONFIG_X86_SGX_KVM
int sgx_virt_ecreate(struct sgx_pageinfo *pageinfo, void __user *secs,
		     int *trapnr);
int sgx_virt_einit(void __user *sigstruct, void __user *token,
		   void __user *secs, u64 *lepubkeyhash, int *trapnr);
#endif

int sgx_set_attribute(unsigned long *allowed_attributes,
		      unsigned int attribute_fd);

#endif /* _ASM_X86_SGX_H */
