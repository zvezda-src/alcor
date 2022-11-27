#include <linux/debugfs.h>		/* debugfs_create_u32()		*/
#include <linux/mm_types.h>             /* mm_struct, vma, etc...       */
#include <linux/pkeys.h>                /* PKEY_*                       */
#include <uapi/asm-generic/mman-common.h>

#include <asm/cpufeature.h>             /* boot_cpu_has, ...            */
#include <asm/mmu_context.h>            /* vma_pkey()                   */

int __execute_only_pkey(struct mm_struct *mm)
{
	bool need_to_set_mm_pkey = false;
	int execute_only_pkey = mm->context.execute_only_pkey;
	int ret;

	/* Do we need to assign a pkey for mm's execute-only maps? */
	if (execute_only_pkey == -1) {
		/* Go allocate one to use, which might fail */
		execute_only_pkey = mm_pkey_alloc(mm);
		if (execute_only_pkey < 0)
			return -1;
		need_to_set_mm_pkey = true;
	}

	/*
	if (!need_to_set_mm_pkey &&
	    !__pkru_allows_read(read_pkru(), execute_only_pkey)) {
		return execute_only_pkey;
	}

	/*
	ret = arch_set_user_pkey_access(current, execute_only_pkey,
			PKEY_DISABLE_ACCESS);
	/*
	if (ret) {
		mm_set_pkey_free(mm, execute_only_pkey);
		return -1;
	}

	/* We got one, store it and use it from here on out */
	if (need_to_set_mm_pkey)
		mm->context.execute_only_pkey = execute_only_pkey;
	return execute_only_pkey;
}

static inline bool vma_is_pkey_exec_only(struct vm_area_struct *vma)
{
	/* Do this check first since the vm_flags should be hot */
	if ((vma->vm_flags & VM_ACCESS_FLAGS) != VM_EXEC)
		return false;
	if (vma_pkey(vma) != vma->vm_mm->context.execute_only_pkey)
		return false;

	return true;
}

int __arch_override_mprotect_pkey(struct vm_area_struct *vma, int prot, int pkey)
{
	/*
	if (pkey != -1)
		return pkey;

	/*
	if (prot == PROT_EXEC) {
		pkey = execute_only_pkey(vma->vm_mm);
		if (pkey > 0)
			return pkey;
	} else if (vma_is_pkey_exec_only(vma)) {
		/*
		return ARCH_DEFAULT_PKEY;
	}

	/*
	return vma_pkey(vma);
}

#define PKRU_AD_MASK(pkey)	(PKRU_AD_BIT << ((pkey) * PKRU_BITS_PER_PKEY))

u32 init_pkru_value = PKRU_AD_MASK( 1) | PKRU_AD_MASK( 2) |
		      PKRU_AD_MASK( 3) | PKRU_AD_MASK( 4) |
		      PKRU_AD_MASK( 5) | PKRU_AD_MASK( 6) |
		      PKRU_AD_MASK( 7) | PKRU_AD_MASK( 8) |
		      PKRU_AD_MASK( 9) | PKRU_AD_MASK(10) |
		      PKRU_AD_MASK(11) | PKRU_AD_MASK(12) |
		      PKRU_AD_MASK(13) | PKRU_AD_MASK(14) |
		      PKRU_AD_MASK(15);

static ssize_t init_pkru_read_file(struct file *file, char __user *user_buf,
			     size_t count, loff_t *ppos)
{
	char buf[32];
	unsigned int len;

	len = sprintf(buf, "0x%x\n", init_pkru_value);
	return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

static ssize_t init_pkru_write_file(struct file *file,
		 const char __user *user_buf, size_t count, loff_t *ppos)
{
	char buf[32];
	ssize_t len;
	u32 new_init_pkru;

	len = min(count, sizeof(buf) - 1);
	if (copy_from_user(buf, user_buf, len))
		return -EFAULT;

	/* Make the buffer a valid string that we can not overrun */
	buf[len] = '\0';
	if (kstrtouint(buf, 0, &new_init_pkru))
		return -EINVAL;

	/*
	if (new_init_pkru & (PKRU_AD_BIT|PKRU_WD_BIT))
		return -EINVAL;

	WRITE_ONCE(init_pkru_value, new_init_pkru);
	return count;
}

static const struct file_operations fops_init_pkru = {
	.read = init_pkru_read_file,
	.write = init_pkru_write_file,
	.llseek = default_llseek,
};

static int __init create_init_pkru_value(void)
{
	/* Do not expose the file if pkeys are not supported. */
	if (!cpu_feature_enabled(X86_FEATURE_OSPKE))
		return 0;

	debugfs_create_file("init_pkru", S_IRUSR | S_IWUSR,
			arch_debugfs_dir, NULL, &fops_init_pkru);
	return 0;
}
late_initcall(create_init_pkru_value);

static __init int setup_init_pkru(char *opt)
{
	u32 new_init_pkru;

	if (kstrtouint(opt, 0, &new_init_pkru))
		return 1;

	WRITE_ONCE(init_pkru_value, new_init_pkru);

	return 1;
}
__setup("init_pkru=", setup_init_pkru);
