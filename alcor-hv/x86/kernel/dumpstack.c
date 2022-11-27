#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/utsname.h>
#include <linux/hardirq.h>
#include <linux/kdebug.h>
#include <linux/module.h>
#include <linux/ptrace.h>
#include <linux/sched/debug.h>
#include <linux/sched/task_stack.h>
#include <linux/ftrace.h>
#include <linux/kexec.h>
#include <linux/bug.h>
#include <linux/nmi.h>
#include <linux/sysfs.h>
#include <linux/kasan.h>

#include <asm/cpu_entry_area.h>
#include <asm/stacktrace.h>
#include <asm/unwind.h>

int panic_on_unrecovered_nmi;
int panic_on_io_nmi;
static int die_counter;

static struct pt_regs exec_summary_regs;

bool noinstr in_task_stack(unsigned long *stack, struct task_struct *task,
			   struct stack_info *info)
{
	unsigned long *begin = task_stack_page(task);
	unsigned long *end   = task_stack_page(task) + THREAD_SIZE;

	if (stack < begin || stack >= end)
		return false;

	info->type	= STACK_TYPE_TASK;
	info->begin	= begin;
	info->end	= end;
	info->next_sp	= NULL;

	return true;
}

bool noinstr in_entry_stack(unsigned long *stack, struct stack_info *info)
{
	struct entry_stack *ss = cpu_entry_stack(smp_processor_id());

	void *begin = ss;
	void *end = ss + 1;

	if ((void *)stack < begin || (void *)stack >= end)
		return false;

	info->type	= STACK_TYPE_ENTRY;
	info->begin	= begin;
	info->end	= end;
	info->next_sp	= NULL;

	return true;
}

static void printk_stack_address(unsigned long address, int reliable,
				 const char *log_lvl)
{
	touch_nmi_watchdog();
	printk("%s %s%pBb\n", log_lvl, reliable ? "" : "? ", (void *)address);
}

static int copy_code(struct pt_regs *regs, u8 *buf, unsigned long src,
		     unsigned int nbytes)
{
	if (!user_mode(regs))
		return copy_from_kernel_nofault(buf, (u8 *)src, nbytes);

	/* The user space code from other tasks cannot be accessed. */
	if (regs != task_pt_regs(current))
		return -EPERM;

	/*
	return copy_from_user_nmi(buf, (void __user *)src, nbytes);
}

void show_opcodes(struct pt_regs *regs, const char *loglvl)
{
#define PROLOGUE_SIZE 42
#define EPILOGUE_SIZE 21
#define OPCODE_BUFSIZE (PROLOGUE_SIZE + 1 + EPILOGUE_SIZE)
	u8 opcodes[OPCODE_BUFSIZE];
	unsigned long prologue = regs->ip - PROLOGUE_SIZE;

	switch (copy_code(regs, opcodes, prologue, sizeof(opcodes))) {
	case 0:
		printk("%sCode: %" __stringify(PROLOGUE_SIZE) "ph <%02x> %"
		       __stringify(EPILOGUE_SIZE) "ph\n", loglvl, opcodes,
		       opcodes[PROLOGUE_SIZE], opcodes + PROLOGUE_SIZE + 1);
		break;
	case -EPERM:
		/* No access to the user space stack of other tasks. Ignore. */
		break;
	default:
		printk("%sCode: Unable to access opcode bytes at RIP 0x%lx.\n",
		       loglvl, prologue);
		break;
	}
}

void show_ip(struct pt_regs *regs, const char *loglvl)
{
#ifdef CONFIG_X86_32
	printk("%sEIP: %pS\n", loglvl, (void *)regs->ip);
#else
	printk("%sRIP: %04x:%pS\n", loglvl, (int)regs->cs, (void *)regs->ip);
#endif
	show_opcodes(regs, loglvl);
}

void show_iret_regs(struct pt_regs *regs, const char *log_lvl)
{
	show_ip(regs, log_lvl);
	printk("%sRSP: %04x:%016lx EFLAGS: %08lx", log_lvl, (int)regs->ss,
		regs->sp, regs->flags);
}

static void show_regs_if_on_stack(struct stack_info *info, struct pt_regs *regs,
				  bool partial, const char *log_lvl)
{
	/*
	if (!partial && on_stack(info, regs, sizeof(*regs))) {
		__show_regs(regs, SHOW_REGS_SHORT, log_lvl);

	} else if (partial && on_stack(info, (void *)regs + IRET_FRAME_OFFSET,
				       IRET_FRAME_SIZE)) {
		/*
		show_iret_regs(regs, log_lvl);
	}
}

static void show_trace_log_lvl(struct task_struct *task, struct pt_regs *regs,
			unsigned long *stack, const char *log_lvl)
{
	struct unwind_state state;
	struct stack_info stack_info = {0};
	unsigned long visit_mask = 0;
	int graph_idx = 0;
	bool partial = false;

	printk("%sCall Trace:\n", log_lvl);

	unwind_start(&state, task, regs, stack);
	stack = stack ? : get_stack_pointer(task, regs);
	regs = unwind_get_entry_regs(&state, &partial);

	/*
	for ( ; stack; stack = PTR_ALIGN(stack_info.next_sp, sizeof(long))) {
		const char *stack_name;

		if (get_stack_info(stack, task, &stack_info, &visit_mask)) {
			/*
			stack = (unsigned long *)PAGE_ALIGN((unsigned long)stack);
			if (get_stack_info(stack, task, &stack_info, &visit_mask))
				break;
		}

		stack_name = stack_type_name(stack_info.type);
		if (stack_name)
			printk("%s <%s>\n", log_lvl, stack_name);

		if (regs)
			show_regs_if_on_stack(&stack_info, regs, partial, log_lvl);

		/*
		for (; stack < stack_info.end; stack++) {
			unsigned long real_addr;
			int reliable = 0;
			unsigned long addr = READ_ONCE_NOCHECK(*stack);
			unsigned long *ret_addr_p =
				unwind_get_return_address_ptr(&state);

			if (!__kernel_text_address(addr))
				continue;

			/*
			if (regs && stack == &regs->ip)
				goto next;

			if (stack == ret_addr_p)
				reliable = 1;

			/*
			real_addr = ftrace_graph_ret_addr(task, &graph_idx,
							  addr, stack);
			if (real_addr != addr)
				printk_stack_address(addr, 0, log_lvl);
			printk_stack_address(real_addr, reliable, log_lvl);

			if (!reliable)
				continue;

next:
			/*
			unwind_next_frame(&state);

			/* if the frame has entry regs, print them */
			regs = unwind_get_entry_regs(&state, &partial);
			if (regs)
				show_regs_if_on_stack(&stack_info, regs, partial, log_lvl);
		}

		if (stack_name)
			printk("%s </%s>\n", log_lvl, stack_name);
	}
}

void show_stack(struct task_struct *task, unsigned long *sp,
		       const char *loglvl)
{
	task = task ? : current;

	/*
	if (!sp && task == current)
		sp = get_stack_pointer(current, NULL);

	show_trace_log_lvl(task, NULL, sp, loglvl);
}

void show_stack_regs(struct pt_regs *regs)
{
	show_trace_log_lvl(current, regs, NULL, KERN_DEFAULT);
}

static arch_spinlock_t die_lock = __ARCH_SPIN_LOCK_UNLOCKED;
static int die_owner = -1;
static unsigned int die_nest_count;

unsigned long oops_begin(void)
{
	int cpu;
	unsigned long flags;

	oops_enter();

	/* racy, but better than risking deadlock. */
	raw_local_irq_save(flags);
	cpu = smp_processor_id();
	if (!arch_spin_trylock(&die_lock)) {
		if (cpu == die_owner)
			/* nested oops. should stop eventually */;
		else
			arch_spin_lock(&die_lock);
	}
	die_nest_count++;
	die_owner = cpu;
	console_verbose();
	bust_spinlocks(1);
	return flags;
}
NOKPROBE_SYMBOL(oops_begin);

void __noreturn rewind_stack_and_make_dead(int signr);

void oops_end(unsigned long flags, struct pt_regs *regs, int signr)
{
	if (regs && kexec_should_crash(current))
		crash_kexec(regs);

	bust_spinlocks(0);
	die_owner = -1;
	add_taint(TAINT_DIE, LOCKDEP_NOW_UNRELIABLE);
	die_nest_count--;
	if (!die_nest_count)
		/* Nest count reaches zero, release the lock. */
		arch_spin_unlock(&die_lock);
	raw_local_irq_restore(flags);
	oops_exit();

	/* Executive summary in case the oops scrolled away */
	__show_regs(&exec_summary_regs, SHOW_REGS_ALL, KERN_DEFAULT);

	if (!signr)
		return;
	if (in_interrupt())
		panic("Fatal exception in interrupt");
	if (panic_on_oops)
		panic("Fatal exception");

	/*
	kasan_unpoison_task_stack(current);
	rewind_stack_and_make_dead(signr);
}
NOKPROBE_SYMBOL(oops_end);

static void __die_header(const char *str, struct pt_regs *regs, long err)
{
	const char *pr = "";

	/* Save the regs of the first oops for the executive summary later. */
	if (!die_counter)
		exec_summary_regs = *regs;

	if (IS_ENABLED(CONFIG_PREEMPTION))
		pr = IS_ENABLED(CONFIG_PREEMPT_RT) ? " PREEMPT_RT" : " PREEMPT";

	printk(KERN_DEFAULT
	       "%s: %04lx [#%d]%s%s%s%s%s\n", str, err & 0xffff, ++die_counter,
	       pr,
	       IS_ENABLED(CONFIG_SMP)     ? " SMP"             : "",
	       debug_pagealloc_enabled()  ? " DEBUG_PAGEALLOC" : "",
	       IS_ENABLED(CONFIG_KASAN)   ? " KASAN"           : "",
	       IS_ENABLED(CONFIG_PAGE_TABLE_ISOLATION) ?
	       (boot_cpu_has(X86_FEATURE_PTI) ? " PTI" : " NOPTI") : "");
}
NOKPROBE_SYMBOL(__die_header);

static int __die_body(const char *str, struct pt_regs *regs, long err)
{
	show_regs(regs);
	print_modules();

	if (notify_die(DIE_OOPS, str, regs, err,
			current->thread.trap_nr, SIGSEGV) == NOTIFY_STOP)
		return 1;

	return 0;
}
NOKPROBE_SYMBOL(__die_body);

int __die(const char *str, struct pt_regs *regs, long err)
{
	__die_header(str, regs, err);
	return __die_body(str, regs, err);
}
NOKPROBE_SYMBOL(__die);

void die(const char *str, struct pt_regs *regs, long err)
{
	unsigned long flags = oops_begin();
	int sig = SIGSEGV;

	if (__die(str, regs, err))
		sig = 0;
	oops_end(flags, regs, sig);
}

void die_addr(const char *str, struct pt_regs *regs, long err, long gp_addr)
{
	unsigned long flags = oops_begin();
	int sig = SIGSEGV;

	__die_header(str, regs, err);
	if (gp_addr)
		kasan_non_canonical_hook(gp_addr);
	if (__die_body(str, regs, err))
		sig = 0;
	oops_end(flags, regs, sig);
}

void show_regs(struct pt_regs *regs)
{
	enum show_regs_mode print_kernel_regs;

	show_regs_print_info(KERN_DEFAULT);

	print_kernel_regs = user_mode(regs) ? SHOW_REGS_USER : SHOW_REGS_ALL;
	__show_regs(regs, print_kernel_regs, KERN_DEFAULT);

	/*
	if (!user_mode(regs))
		show_trace_log_lvl(current, regs, NULL, KERN_DEFAULT);
}
