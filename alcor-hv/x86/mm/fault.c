#include <linux/sched.h>		/* test_thread_flag(), ...	*/
#include <linux/sched/task_stack.h>	/* task_stack_*(), ...		*/
#include <linux/kdebug.h>		/* oops_begin/end, ...		*/
#include <linux/extable.h>		/* search_exception_tables	*/
#include <linux/memblock.h>		/* max_low_pfn			*/
#include <linux/kfence.h>		/* kfence_handle_page_fault	*/
#include <linux/kprobes.h>		/* NOKPROBE_SYMBOL, ...		*/
#include <linux/mmiotrace.h>		/* kmmio_handler, ...		*/
#include <linux/perf_event.h>		/* perf_sw_event		*/
#include <linux/hugetlb.h>		/* hstate_index_to_shift	*/
#include <linux/prefetch.h>		/* prefetchw			*/
#include <linux/context_tracking.h>	/* exception_enter(), ...	*/
#include <linux/uaccess.h>		/* faulthandler_disabled()	*/
#include <linux/efi.h>			/* efi_crash_gracefully_on_page_fault()*/
#include <linux/mm_types.h>

#include <asm/cpufeature.h>		/* boot_cpu_has, ...		*/
#include <asm/traps.h>			/* dotraplinkage, ...		*/
#include <asm/fixmap.h>			/* VSYSCALL_ADDR		*/
#include <asm/vsyscall.h>		/* emulate_vsyscall		*/
#include <asm/vm86.h>			/* struct vm86			*/
#include <asm/mmu_context.h>		/* vma_pkey()			*/
#include <asm/efi.h>			/* efi_crash_gracefully_on_page_fault()*/
#include <asm/desc.h>			/* store_idt(), ...		*/
#include <asm/cpu_entry_area.h>		/* exception stack		*/
#include <asm/pgtable_areas.h>		/* VMALLOC_START, ...		*/
#include <asm/kvm_para.h>		/* kvm_handle_async_pf		*/
#include <asm/vdso.h>			/* fixup_vdso_exception()	*/
#include <asm/irq_stack.h>

#define CREATE_TRACE_POINTS
#include <asm/trace/exceptions.h>

static nokprobe_inline int
kmmio_fault(struct pt_regs *regs, unsigned long addr)
{
	if (unlikely(is_kmmio_active()))
		if (kmmio_handler(regs, addr) == 1)
			return -1;
	return 0;
}

static inline int
check_prefetch_opcode(struct pt_regs *regs, unsigned char *instr,
		      unsigned char opcode, int *prefetch)
{
	unsigned char instr_hi = opcode & 0xf0;
	unsigned char instr_lo = opcode & 0x0f;

	switch (instr_hi) {
	case 0x20:
	case 0x30:
		/*
		return ((instr_lo & 7) == 0x6);
#ifdef CONFIG_X86_64
	case 0x40:
		/*
		return (!user_mode(regs) || user_64bit_mode(regs));
#endif
	case 0x60:
		/* 0x64 thru 0x67 are valid prefixes in all modes. */
		return (instr_lo & 0xC) == 0x4;
	case 0xF0:
		/* 0xF0, 0xF2, 0xF3 are valid prefixes in all modes. */
		return !instr_lo || (instr_lo>>1) == 1;
	case 0x00:
		/* Prefetch instruction is 0x0F0D or 0x0F18 */
		if (get_kernel_nofault(opcode, instr))
			return 0;

		*prefetch = (instr_lo == 0xF) &&
			(opcode == 0x0D || opcode == 0x18);
		return 0;
	default:
		return 0;
	}
}

static bool is_amd_k8_pre_npt(void)
{
	struct cpuinfo_x86 *c = &boot_cpu_data;

	return unlikely(IS_ENABLED(CONFIG_CPU_SUP_AMD) &&
			c->x86_vendor == X86_VENDOR_AMD &&
			c->x86 == 0xf && c->x86_model < 0x40);
}

static int
is_prefetch(struct pt_regs *regs, unsigned long error_code, unsigned long addr)
{
	unsigned char *max_instr;
	unsigned char *instr;
	int prefetch = 0;

	/* Erratum #91 affects AMD K8, pre-NPT CPUs */
	if (!is_amd_k8_pre_npt())
		return 0;

	/*
	if (error_code & X86_PF_INSTR)
		return 0;

	instr = (void *)convert_ip_to_linear(current, regs);
	max_instr = instr + 15;

	/*
	pagefault_disable();

	while (instr < max_instr) {
		unsigned char opcode;

		if (user_mode(regs)) {
			if (get_user(opcode, (unsigned char __user *) instr))
				break;
		} else {
			if (get_kernel_nofault(opcode, instr))
				break;
		}

		instr++;

		if (!check_prefetch_opcode(regs, instr, opcode, &prefetch))
			break;
	}

	pagefault_enable();
	return prefetch;
}

DEFINE_SPINLOCK(pgd_lock);
LIST_HEAD(pgd_list);

#ifdef CONFIG_X86_32
static inline pmd_t *vmalloc_sync_one(pgd_t *pgd, unsigned long address)
{
	unsigned index = pgd_index(address);
	pgd_t *pgd_k;
	p4d_t *p4d, *p4d_k;
	pud_t *pud, *pud_k;
	pmd_t *pmd, *pmd_k;

	pgd += index;
	pgd_k = init_mm.pgd + index;

	if (!pgd_present(*pgd_k))
		return NULL;

	/*
	p4d = p4d_offset(pgd, address);
	p4d_k = p4d_offset(pgd_k, address);
	if (!p4d_present(*p4d_k))
		return NULL;

	pud = pud_offset(p4d, address);
	pud_k = pud_offset(p4d_k, address);
	if (!pud_present(*pud_k))
		return NULL;

	pmd = pmd_offset(pud, address);
	pmd_k = pmd_offset(pud_k, address);

	if (pmd_present(*pmd) != pmd_present(*pmd_k))
		set_pmd(pmd, *pmd_k);

	if (!pmd_present(*pmd_k))
		return NULL;
	else
		BUG_ON(pmd_pfn(*pmd) != pmd_pfn(*pmd_k));

	return pmd_k;
}

static noinline int vmalloc_fault(unsigned long address)
{
	unsigned long pgd_paddr;
	pmd_t *pmd_k;
	pte_t *pte_k;

	/* Make sure we are in vmalloc area: */
	if (!(address >= VMALLOC_START && address < VMALLOC_END))
		return -1;

	/*
	pgd_paddr = read_cr3_pa();
	pmd_k = vmalloc_sync_one(__va(pgd_paddr), address);
	if (!pmd_k)
		return -1;

	if (pmd_large(*pmd_k))
		return 0;

	pte_k = pte_offset_kernel(pmd_k, address);
	if (!pte_present(*pte_k))
		return -1;

	return 0;
}
NOKPROBE_SYMBOL(vmalloc_fault);

void arch_sync_kernel_mappings(unsigned long start, unsigned long end)
{
	unsigned long addr;

	for (addr = start & PMD_MASK;
	     addr >= TASK_SIZE_MAX && addr < VMALLOC_END;
	     addr += PMD_SIZE) {
		struct page *page;

		spin_lock(&pgd_lock);
		list_for_each_entry(page, &pgd_list, lru) {
			spinlock_t *pgt_lock;

			/* the pgt_lock only for Xen */
			pgt_lock = &pgd_page_get_mm(page)->page_table_lock;

			spin_lock(pgt_lock);
			vmalloc_sync_one(page_address(page), addr);
			spin_unlock(pgt_lock);
		}
		spin_unlock(&pgd_lock);
	}
}

static bool low_pfn(unsigned long pfn)
{
	return pfn < max_low_pfn;
}

static void dump_pagetable(unsigned long address)
{
	pgd_t *base = __va(read_cr3_pa());
	pgd_t *pgd = &base[pgd_index(address)];
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

#ifdef CONFIG_X86_PAE
	pr_info("*pdpt = %016Lx ", pgd_val(*pgd));
	if (!low_pfn(pgd_val(*pgd) >> PAGE_SHIFT) || !pgd_present(*pgd))
		goto out;
#define pr_pde pr_cont
#else
#define pr_pde pr_info
#endif
	p4d = p4d_offset(pgd, address);
	pud = pud_offset(p4d, address);
	pmd = pmd_offset(pud, address);
	pr_pde("*pde = %0*Lx ", sizeof(*pmd) * 2, (u64)pmd_val(*pmd));
#undef pr_pde

	/*
	if (!low_pfn(pmd_pfn(*pmd)) || !pmd_present(*pmd) || pmd_large(*pmd))
		goto out;

	pte = pte_offset_kernel(pmd, address);
	pr_cont("*pte = %0*Lx ", sizeof(*pte) * 2, (u64)pte_val(*pte));
out:
	pr_cont("\n");
}

#else /* CONFIG_X86_64: */

#ifdef CONFIG_CPU_SUP_AMD
static const char errata93_warning[] =
KERN_ERR 
"******* Your BIOS seems to not contain a fix for K8 errata #93\n"
"******* Working around it, but it may cause SEGVs or burn power.\n"
"******* Please consider a BIOS update.\n"
"******* Disabling USB legacy in the BIOS may also help.\n";
#endif

static int bad_address(void *p)
{
	unsigned long dummy;

	return get_kernel_nofault(dummy, (unsigned long *)p);
}

static void dump_pagetable(unsigned long address)
{
	pgd_t *base = __va(read_cr3_pa());
	pgd_t *pgd = base + pgd_index(address);
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	if (bad_address(pgd))
		goto bad;

	pr_info("PGD %lx ", pgd_val(*pgd));

	if (!pgd_present(*pgd))
		goto out;

	p4d = p4d_offset(pgd, address);
	if (bad_address(p4d))
		goto bad;

	pr_cont("P4D %lx ", p4d_val(*p4d));
	if (!p4d_present(*p4d) || p4d_large(*p4d))
		goto out;

	pud = pud_offset(p4d, address);
	if (bad_address(pud))
		goto bad;

	pr_cont("PUD %lx ", pud_val(*pud));
	if (!pud_present(*pud) || pud_large(*pud))
		goto out;

	pmd = pmd_offset(pud, address);
	if (bad_address(pmd))
		goto bad;

	pr_cont("PMD %lx ", pmd_val(*pmd));
	if (!pmd_present(*pmd) || pmd_large(*pmd))
		goto out;

	pte = pte_offset_kernel(pmd, address);
	if (bad_address(pte))
		goto bad;

	pr_cont("PTE %lx", pte_val(*pte));
out:
	pr_cont("\n");
	return;
bad:
	pr_info("BAD\n");
}

#endif /* CONFIG_X86_64 */

static int is_errata93(struct pt_regs *regs, unsigned long address)
{
#if defined(CONFIG_X86_64) && defined(CONFIG_CPU_SUP_AMD)
	if (boot_cpu_data.x86_vendor != X86_VENDOR_AMD
	    || boot_cpu_data.x86 != 0xf)
		return 0;

	if (user_mode(regs))
		return 0;

	if (address != regs->ip)
		return 0;

	if ((address >> 32) != 0)
		return 0;

	address |= 0xffffffffUL << 32;
	if ((address >= (u64)_stext && address <= (u64)_etext) ||
	    (address >= MODULES_VADDR && address <= MODULES_END)) {
		printk_once(errata93_warning);
		regs->ip = address;
		return 1;
	}
#endif
	return 0;
}

static int is_errata100(struct pt_regs *regs, unsigned long address)
{
#ifdef CONFIG_X86_64
	if ((regs->cs == __USER32_CS || (regs->cs & (1<<2))) && (address >> 32))
		return 1;
#endif
	return 0;
}

static int is_f00f_bug(struct pt_regs *regs, unsigned long error_code,
		       unsigned long address)
{
#ifdef CONFIG_X86_F00F_BUG
	if (boot_cpu_has_bug(X86_BUG_F00F) && !(error_code & X86_PF_USER) &&
	    idt_is_f00f_address(address)) {
		handle_invalid_op(regs);
		return 1;
	}
#endif
	return 0;
}

static void show_ldttss(const struct desc_ptr *gdt, const char *name, u16 index)
{
	u32 offset = (index >> 3) * sizeof(struct desc_struct);
	unsigned long addr;
	struct ldttss_desc desc;

	if (index == 0) {
		pr_alert("%s: NULL\n", name);
		return;
	}

	if (offset + sizeof(struct ldttss_desc) >= gdt->size) {
		pr_alert("%s: 0x%hx -- out of bounds\n", name, index);
		return;
	}

	if (copy_from_kernel_nofault(&desc, (void *)(gdt->address + offset),
			      sizeof(struct ldttss_desc))) {
		pr_alert("%s: 0x%hx -- GDT entry is not readable\n",
			 name, index);
		return;
	}

	addr = desc.base0 | (desc.base1 << 16) | ((unsigned long)desc.base2 << 24);
#ifdef CONFIG_X86_64
	addr |= ((u64)desc.base3 << 32);
#endif
	pr_alert("%s: 0x%hx -- base=0x%lx limit=0x%x\n",
		 name, index, addr, (desc.limit0 | (desc.limit1 << 16)));
}

static void
show_fault_oops(struct pt_regs *regs, unsigned long error_code, unsigned long address)
{
	if (!oops_may_print())
		return;

	if (error_code & X86_PF_INSTR) {
		unsigned int level;
		pgd_t *pgd;
		pte_t *pte;

		pgd = __va(read_cr3_pa());
		pgd += pgd_index(address);

		pte = lookup_address_in_pgd(pgd, address, &level);

		if (pte && pte_present(*pte) && !pte_exec(*pte))
			pr_crit("kernel tried to execute NX-protected page - exploit attempt? (uid: %d)\n",
				from_kuid(&init_user_ns, current_uid()));
		if (pte && pte_present(*pte) && pte_exec(*pte) &&
				(pgd_flags(*pgd) & _PAGE_USER) &&
				(__read_cr4() & X86_CR4_SMEP))
			pr_crit("unable to execute userspace code (SMEP?) (uid: %d)\n",
				from_kuid(&init_user_ns, current_uid()));
	}

	if (address < PAGE_SIZE && !user_mode(regs))
		pr_alert("BUG: kernel NULL pointer dereference, address: %px\n",
			(void *)address);
	else
		pr_alert("BUG: unable to handle page fault for address: %px\n",
			(void *)address);

	pr_alert("#PF: %s %s in %s mode\n",
		 (error_code & X86_PF_USER)  ? "user" : "supervisor",
		 (error_code & X86_PF_INSTR) ? "instruction fetch" :
		 (error_code & X86_PF_WRITE) ? "write access" :
					       "read access",
			     user_mode(regs) ? "user" : "kernel");
	pr_alert("#PF: error_code(0x%04lx) - %s\n", error_code,
		 !(error_code & X86_PF_PROT) ? "not-present page" :
		 (error_code & X86_PF_RSVD)  ? "reserved bit violation" :
		 (error_code & X86_PF_PK)    ? "protection keys violation" :
					       "permissions violation");

	if (!(error_code & X86_PF_USER) && user_mode(regs)) {
		struct desc_ptr idt, gdt;
		u16 ldtr, tr;

		/*
		store_idt(&idt);

		/* Usable even on Xen PV -- it's just slow. */
		native_store_gdt(&gdt);

		pr_alert("IDT: 0x%lx (limit=0x%hx) GDT: 0x%lx (limit=0x%hx)\n",
			 idt.address, idt.size, gdt.address, gdt.size);

		store_ldt(ldtr);
		show_ldttss(&gdt, "LDTR", ldtr);

		store_tr(tr);
		show_ldttss(&gdt, "TR", tr);
	}

	dump_pagetable(address);
}

static noinline void
pgtable_bad(struct pt_regs *regs, unsigned long error_code,
	    unsigned long address)
{
	struct task_struct *tsk;
	unsigned long flags;
	int sig;

	flags = oops_begin();
	tsk = current;
	sig = SIGKILL;

	printk(KERN_ALERT "%s: Corrupted page table at address %lx\n",
	       tsk->comm, address);
	dump_pagetable(address);

	if (__die("Bad pagetable", regs, error_code))
		sig = 0;

	oops_end(flags, regs, sig);
}

static void sanitize_error_code(unsigned long address,
				unsigned long *error_code)
{
	/*
	if (address >= TASK_SIZE_MAX)
		*error_code |= X86_PF_PROT;
}

static void set_signal_archinfo(unsigned long address,
				unsigned long error_code)
{
	struct task_struct *tsk = current;

	tsk->thread.trap_nr = X86_TRAP_PF;
	tsk->thread.error_code = error_code | X86_PF_USER;
	tsk->thread.cr2 = address;
}

static noinline void
page_fault_oops(struct pt_regs *regs, unsigned long error_code,
		unsigned long address)
{
#ifdef CONFIG_VMAP_STACK
	struct stack_info info;
#endif
	unsigned long flags;
	int sig;

	if (user_mode(regs)) {
		/*
		goto oops;
	}

#ifdef CONFIG_VMAP_STACK
	/*
	if (is_vmalloc_addr((void *)address) &&
	    get_stack_guard_info((void *)address, &info)) {
		/*
		call_on_stack(__this_cpu_ist_top_va(DF) - sizeof(void*),
			      handle_stack_overflow,
			      ASM_CALL_ARG3,
			      , [arg1] "r" (regs), [arg2] "r" (address), [arg3] "r" (&info));

		unreachable();
	}
#endif

	/*
	if (IS_ENABLED(CONFIG_EFI))
		efi_crash_gracefully_on_page_fault(address);

	/* Only not-present faults should be handled by KFENCE. */
	if (!(error_code & X86_PF_PROT) &&
	    kfence_handle_page_fault(address, error_code & X86_PF_WRITE, regs))
		return;

oops:
	/*
	flags = oops_begin();

	show_fault_oops(regs, error_code, address);

	if (task_stack_end_corrupted(current))
		printk(KERN_EMERG "Thread overran stack, or stack corrupted\n");

	sig = SIGKILL;
	if (__die("Oops", regs, error_code))
		sig = 0;

	/* Executive summary in case the body of the oops scrolled away */
	printk(KERN_DEFAULT "CR2: %016lx\n", address);

	oops_end(flags, regs, sig);
}

static noinline void
kernelmode_fixup_or_oops(struct pt_regs *regs, unsigned long error_code,
			 unsigned long address, int signal, int si_code,
			 u32 pkey)
{
	WARN_ON_ONCE(user_mode(regs));

	/* Are we prepared to handle this kernel fault? */
	if (fixup_exception(regs, X86_TRAP_PF, error_code, address)) {
		/*
		if (in_interrupt())
			return;

		/*
		if (current->thread.sig_on_uaccess_err && signal) {
			sanitize_error_code(address, &error_code);

			set_signal_archinfo(address, error_code);

			if (si_code == SEGV_PKUERR) {
				force_sig_pkuerr((void __user *)address, pkey);
			} else {
				/* XXX: hwpoison faults will set the wrong code. */
				force_sig_fault(signal, si_code, (void __user *)address);
			}
		}

		/*
		return;
	}

	/*
	if (is_prefetch(regs, error_code, address))
		return;

	page_fault_oops(regs, error_code, address);
}

static inline void
show_signal_msg(struct pt_regs *regs, unsigned long error_code,
		unsigned long address, struct task_struct *tsk)
{
	const char *loglvl = task_pid_nr(tsk) > 1 ? KERN_INFO : KERN_EMERG;

	if (!unhandled_signal(tsk, SIGSEGV))
		return;

	if (!printk_ratelimit())
		return;

	printk("%s%s[%d]: segfault at %lx ip %px sp %px error %lx",
		loglvl, tsk->comm, task_pid_nr(tsk), address,
		(void *)regs->ip, (void *)regs->sp, error_code);

	print_vma_addr(KERN_CONT " in ", regs->ip);

	printk(KERN_CONT "\n");

	show_opcodes(regs, loglvl);
}

static bool is_vsyscall_vaddr(unsigned long vaddr)
{
	return unlikely((vaddr & PAGE_MASK) == VSYSCALL_ADDR);
}

static void
__bad_area_nosemaphore(struct pt_regs *regs, unsigned long error_code,
		       unsigned long address, u32 pkey, int si_code)
{
	struct task_struct *tsk = current;

	if (!user_mode(regs)) {
		kernelmode_fixup_or_oops(regs, error_code, address,
					 SIGSEGV, si_code, pkey);
		return;
	}

	if (!(error_code & X86_PF_USER)) {
		/* Implicit user access to kernel memory -- just oops */
		page_fault_oops(regs, error_code, address);
		return;
	}

	/*
	local_irq_enable();

	/*
	if (is_prefetch(regs, error_code, address))
		return;

	if (is_errata100(regs, address))
		return;

	sanitize_error_code(address, &error_code);

	if (fixup_vdso_exception(regs, X86_TRAP_PF, error_code, address))
		return;

	if (likely(show_unhandled_signals))
		show_signal_msg(regs, error_code, address, tsk);

	set_signal_archinfo(address, error_code);

	if (si_code == SEGV_PKUERR)
		force_sig_pkuerr((void __user *)address, pkey);
	else
		force_sig_fault(SIGSEGV, si_code, (void __user *)address);

	local_irq_disable();
}

static noinline void
bad_area_nosemaphore(struct pt_regs *regs, unsigned long error_code,
		     unsigned long address)
{
	__bad_area_nosemaphore(regs, error_code, address, 0, SEGV_MAPERR);
}

static void
__bad_area(struct pt_regs *regs, unsigned long error_code,
	   unsigned long address, u32 pkey, int si_code)
{
	struct mm_struct *mm = current->mm;
	/*
	mmap_read_unlock(mm);

	__bad_area_nosemaphore(regs, error_code, address, pkey, si_code);
}

static noinline void
bad_area(struct pt_regs *regs, unsigned long error_code, unsigned long address)
{
	__bad_area(regs, error_code, address, 0, SEGV_MAPERR);
}

static inline bool bad_area_access_from_pkeys(unsigned long error_code,
		struct vm_area_struct *vma)
{
	/* This code is always called on the current mm */
	bool foreign = false;

	if (!cpu_feature_enabled(X86_FEATURE_OSPKE))
		return false;
	if (error_code & X86_PF_PK)
		return true;
	/* this checks permission keys on the VMA: */
	if (!arch_vma_access_permitted(vma, (error_code & X86_PF_WRITE),
				       (error_code & X86_PF_INSTR), foreign))
		return true;
	return false;
}

static noinline void
bad_area_access_error(struct pt_regs *regs, unsigned long error_code,
		      unsigned long address, struct vm_area_struct *vma)
{
	/*
	if (bad_area_access_from_pkeys(error_code, vma)) {
		/*
		u32 pkey = vma_pkey(vma);

		__bad_area(regs, error_code, address, pkey, SEGV_PKUERR);
	} else {
		__bad_area(regs, error_code, address, 0, SEGV_ACCERR);
	}
}

static void
do_sigbus(struct pt_regs *regs, unsigned long error_code, unsigned long address,
	  vm_fault_t fault)
{
	/* Kernel mode? Handle exceptions or die: */
	if (!user_mode(regs)) {
		kernelmode_fixup_or_oops(regs, error_code, address,
					 SIGBUS, BUS_ADRERR, ARCH_DEFAULT_PKEY);
		return;
	}

	/* User-space => ok to do another page fault: */
	if (is_prefetch(regs, error_code, address))
		return;

	sanitize_error_code(address, &error_code);

	if (fixup_vdso_exception(regs, X86_TRAP_PF, error_code, address))
		return;

	set_signal_archinfo(address, error_code);

#ifdef CONFIG_MEMORY_FAILURE
	if (fault & (VM_FAULT_HWPOISON|VM_FAULT_HWPOISON_LARGE)) {
		struct task_struct *tsk = current;
		unsigned lsb = 0;

		pr_err(
	"MCE: Killing %s:%d due to hardware memory corruption fault at %lx\n",
			tsk->comm, tsk->pid, address);
		if (fault & VM_FAULT_HWPOISON_LARGE)
			lsb = hstate_index_to_shift(VM_FAULT_GET_HINDEX(fault));
		if (fault & VM_FAULT_HWPOISON)
			lsb = PAGE_SHIFT;
		force_sig_mceerr(BUS_MCEERR_AR, (void __user *)address, lsb);
		return;
	}
#endif
	force_sig_fault(SIGBUS, BUS_ADRERR, (void __user *)address);
}

static int spurious_kernel_fault_check(unsigned long error_code, pte_t *pte)
{
	if ((error_code & X86_PF_WRITE) && !pte_write(*pte))
		return 0;

	if ((error_code & X86_PF_INSTR) && !pte_exec(*pte))
		return 0;

	return 1;
}

static noinline int
spurious_kernel_fault(unsigned long error_code, unsigned long address)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	int ret;

	/*
	if (error_code != (X86_PF_WRITE | X86_PF_PROT) &&
	    error_code != (X86_PF_INSTR | X86_PF_PROT))
		return 0;

	pgd = init_mm.pgd + pgd_index(address);
	if (!pgd_present(*pgd))
		return 0;

	p4d = p4d_offset(pgd, address);
	if (!p4d_present(*p4d))
		return 0;

	if (p4d_large(*p4d))
		return spurious_kernel_fault_check(error_code, (pte_t *) p4d);

	pud = pud_offset(p4d, address);
	if (!pud_present(*pud))
		return 0;

	if (pud_large(*pud))
		return spurious_kernel_fault_check(error_code, (pte_t *) pud);

	pmd = pmd_offset(pud, address);
	if (!pmd_present(*pmd))
		return 0;

	if (pmd_large(*pmd))
		return spurious_kernel_fault_check(error_code, (pte_t *) pmd);

	pte = pte_offset_kernel(pmd, address);
	if (!pte_present(*pte))
		return 0;

	ret = spurious_kernel_fault_check(error_code, pte);
	if (!ret)
		return 0;

	/*
	ret = spurious_kernel_fault_check(error_code, (pte_t *) pmd);
	WARN_ONCE(!ret, "PMD has incorrect permission bits\n");

	return ret;
}
NOKPROBE_SYMBOL(spurious_kernel_fault);

int show_unhandled_signals = 1;

static inline int
access_error(unsigned long error_code, struct vm_area_struct *vma)
{
	/* This is only called for the current mm, so: */
	bool foreign = false;

	/*
	if (error_code & X86_PF_PK)
		return 1;

	/*
	if (unlikely(error_code & X86_PF_SGX))
		return 1;

	/*
	if (!arch_vma_access_permitted(vma, (error_code & X86_PF_WRITE),
				       (error_code & X86_PF_INSTR), foreign))
		return 1;

	if (error_code & X86_PF_WRITE) {
		/* write, present and write, not present: */
		if (unlikely(!(vma->vm_flags & VM_WRITE)))
			return 1;
		return 0;
	}

	/* read, present: */
	if (unlikely(error_code & X86_PF_PROT))
		return 1;

	/* read, not present: */
	if (unlikely(!vma_is_accessible(vma)))
		return 1;

	return 0;
}

bool fault_in_kernel_space(unsigned long address)
{
	/*
	if (IS_ENABLED(CONFIG_X86_64) && is_vsyscall_vaddr(address))
		return false;

	return address >= TASK_SIZE_MAX;
}

static void
do_kern_addr_fault(struct pt_regs *regs, unsigned long hw_error_code,
		   unsigned long address)
{
	/*
	WARN_ON_ONCE(hw_error_code & X86_PF_PK);

#ifdef CONFIG_X86_32
	/*
	if (!(hw_error_code & (X86_PF_RSVD | X86_PF_USER | X86_PF_PROT))) {
		if (vmalloc_fault(address) >= 0)
			return;
	}
#endif

	if (is_f00f_bug(regs, hw_error_code, address))
		return;

	/* Was the fault spurious, caused by lazy TLB invalidation? */
	if (spurious_kernel_fault(hw_error_code, address))
		return;

	/* kprobes don't want to hook the spurious faults: */
	if (WARN_ON_ONCE(kprobe_page_fault(regs, X86_TRAP_PF)))
		return;

	/*
	bad_area_nosemaphore(regs, hw_error_code, address);
}
NOKPROBE_SYMBOL(do_kern_addr_fault);

static inline
void do_user_addr_fault(struct pt_regs *regs,
			unsigned long error_code,
			unsigned long address)
{
	struct vm_area_struct *vma;
	struct task_struct *tsk;
	struct mm_struct *mm;
	vm_fault_t fault;
	unsigned int flags = FAULT_FLAG_DEFAULT;

	tsk = current;
	mm = tsk->mm;

	if (unlikely((error_code & (X86_PF_USER | X86_PF_INSTR)) == X86_PF_INSTR)) {
		/*
		if (is_errata93(regs, address))
			return;

		page_fault_oops(regs, error_code, address);
		return;
	}

	/* kprobes don't want to hook the spurious faults: */
	if (WARN_ON_ONCE(kprobe_page_fault(regs, X86_TRAP_PF)))
		return;

	/*
	if (unlikely(error_code & X86_PF_RSVD))
		pgtable_bad(regs, error_code, address);

	/*
	if (unlikely(cpu_feature_enabled(X86_FEATURE_SMAP) &&
		     !(error_code & X86_PF_USER) &&
		     !(regs->flags & X86_EFLAGS_AC))) {
		/*
		page_fault_oops(regs, error_code, address);
		return;
	}

	/*
	if (unlikely(faulthandler_disabled() || !mm)) {
		bad_area_nosemaphore(regs, error_code, address);
		return;
	}

	/*
	if (user_mode(regs)) {
		local_irq_enable();
		flags |= FAULT_FLAG_USER;
	} else {
		if (regs->flags & X86_EFLAGS_IF)
			local_irq_enable();
	}

	perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS, 1, regs, address);

	if (error_code & X86_PF_WRITE)
		flags |= FAULT_FLAG_WRITE;
	if (error_code & X86_PF_INSTR)
		flags |= FAULT_FLAG_INSTRUCTION;

#ifdef CONFIG_X86_64
	/*
	if (is_vsyscall_vaddr(address)) {
		if (emulate_vsyscall(error_code, regs, address))
			return;
	}
#endif

	/*
	if (unlikely(!mmap_read_trylock(mm))) {
		if (!user_mode(regs) && !search_exception_tables(regs->ip)) {
			/*
			bad_area_nosemaphore(regs, error_code, address);
			return;
		}
retry:
		mmap_read_lock(mm);
	} else {
		/*
		might_sleep();
	}

	vma = find_vma(mm, address);
	if (unlikely(!vma)) {
		bad_area(regs, error_code, address);
		return;
	}
	if (likely(vma->vm_start <= address))
		goto good_area;
	if (unlikely(!(vma->vm_flags & VM_GROWSDOWN))) {
		bad_area(regs, error_code, address);
		return;
	}
	if (unlikely(expand_stack(vma, address))) {
		bad_area(regs, error_code, address);
		return;
	}

	/*
good_area:
	if (unlikely(access_error(error_code, vma))) {
		bad_area_access_error(regs, error_code, address, vma);
		return;
	}

	/*
	fault = handle_mm_fault(vma, address, flags, regs);

	if (fault_signal_pending(fault, regs)) {
		/*
		if (!user_mode(regs))
			kernelmode_fixup_or_oops(regs, error_code, address,
						 SIGBUS, BUS_ADRERR,
						 ARCH_DEFAULT_PKEY);
		return;
	}

	/* The fault is fully completed (including releasing mmap lock) */
	if (fault & VM_FAULT_COMPLETED)
		return;

	/*
	if (unlikely(fault & VM_FAULT_RETRY)) {
		flags |= FAULT_FLAG_TRIED;
		goto retry;
	}

	mmap_read_unlock(mm);
	if (likely(!(fault & VM_FAULT_ERROR)))
		return;

	if (fatal_signal_pending(current) && !user_mode(regs)) {
		kernelmode_fixup_or_oops(regs, error_code, address,
					 0, 0, ARCH_DEFAULT_PKEY);
		return;
	}

	if (fault & VM_FAULT_OOM) {
		/* Kernel mode? Handle exceptions or die: */
		if (!user_mode(regs)) {
			kernelmode_fixup_or_oops(regs, error_code, address,
						 SIGSEGV, SEGV_MAPERR,
						 ARCH_DEFAULT_PKEY);
			return;
		}

		/*
		pagefault_out_of_memory();
	} else {
		if (fault & (VM_FAULT_SIGBUS|VM_FAULT_HWPOISON|
			     VM_FAULT_HWPOISON_LARGE))
			do_sigbus(regs, error_code, address, fault);
		else if (fault & VM_FAULT_SIGSEGV)
			bad_area_nosemaphore(regs, error_code, address);
		else
			BUG();
	}
}
NOKPROBE_SYMBOL(do_user_addr_fault);

static __always_inline void
trace_page_fault_entries(struct pt_regs *regs, unsigned long error_code,
			 unsigned long address)
{
	if (!trace_pagefault_enabled())
		return;

	if (user_mode(regs))
		trace_page_fault_user(address, regs, error_code);
	else
		trace_page_fault_kernel(address, regs, error_code);
}

static __always_inline void
handle_page_fault(struct pt_regs *regs, unsigned long error_code,
			      unsigned long address)
{
	trace_page_fault_entries(regs, error_code, address);

	if (unlikely(kmmio_fault(regs, address)))
		return;

	/* Was the fault on kernel-controlled part of the address space? */
	if (unlikely(fault_in_kernel_space(address))) {
		do_kern_addr_fault(regs, error_code, address);
	} else {
		do_user_addr_fault(regs, error_code, address);
		/*
		local_irq_disable();
	}
}

DEFINE_IDTENTRY_RAW_ERRORCODE(exc_page_fault)
{
	unsigned long address = read_cr2();
	irqentry_state_t state;

	prefetchw(&current->mm->mmap_lock);

	/*
	if (kvm_handle_async_pf(regs, (u32)address))
		return;

	/*
	state = irqentry_enter(regs);

	instrumentation_begin();
	handle_page_fault(regs, error_code, address);
	instrumentation_end();

	irqentry_exit(regs, state);
}
