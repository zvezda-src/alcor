#define pr_fmt(fmt) "SMP alternatives: " fmt

#include <linux/module.h>
#include <linux/sched.h>
#include <linux/perf_event.h>
#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/stringify.h>
#include <linux/highmem.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/memory.h>
#include <linux/stop_machine.h>
#include <linux/slab.h>
#include <linux/kdebug.h>
#include <linux/kprobes.h>
#include <linux/mmu_context.h>
#include <linux/bsearch.h>
#include <linux/sync_core.h>
#include <asm/text-patching.h>
#include <asm/alternative.h>
#include <asm/sections.h>
#include <asm/mce.h>
#include <asm/nmi.h>
#include <asm/cacheflush.h>
#include <asm/tlbflush.h>
#include <asm/insn.h>
#include <asm/io.h>
#include <asm/fixmap.h>
#include <asm/paravirt.h>
#include <asm/asm-prototypes.h>

int __read_mostly alternatives_patched;

EXPORT_SYMBOL_GPL(alternatives_patched);

#define MAX_PATCH_LEN (255-1)

static int __initdata_or_module debug_alternative;

static int __init debug_alt(char *str)
{
	debug_alternative = 1;
	return 1;
}
__setup("debug-alternative", debug_alt);

static int noreplace_smp;

static int __init setup_noreplace_smp(char *str)
{
	noreplace_smp = 1;
	return 1;
}
__setup("noreplace-smp", setup_noreplace_smp);

#define DPRINTK(fmt, args...)						\
do {									\
	if (debug_alternative)						\
		printk(KERN_DEBUG pr_fmt(fmt) "\n", ##args);		\
} while (0)

#define DUMP_BYTES(buf, len, fmt, args...)				\
do {									\
	if (unlikely(debug_alternative)) {				\
		int j;							\
									\
		if (!(len))						\
			break;						\
									\
		printk(KERN_DEBUG pr_fmt(fmt), ##args);			\
		for (j = 0; j < (len) - 1; j++)				\
			printk(KERN_CONT "%02hhx ", buf[j]);		\
		printk(KERN_CONT "%02hhx\n", buf[j]);			\
	}								\
} while (0)

static const unsigned char x86nops[] =
{
	BYTES_NOP1,
	BYTES_NOP2,
	BYTES_NOP3,
	BYTES_NOP4,
	BYTES_NOP5,
	BYTES_NOP6,
	BYTES_NOP7,
	BYTES_NOP8,
};

const unsigned char * const x86_nops[ASM_NOP_MAX+1] =
{
	NULL,
	x86nops,
	x86nops + 1,
	x86nops + 1 + 2,
	x86nops + 1 + 2 + 3,
	x86nops + 1 + 2 + 3 + 4,
	x86nops + 1 + 2 + 3 + 4 + 5,
	x86nops + 1 + 2 + 3 + 4 + 5 + 6,
	x86nops + 1 + 2 + 3 + 4 + 5 + 6 + 7,
};

static void __init_or_module add_nops(void *insns, unsigned int len)
{
	while (len > 0) {
		unsigned int noplen = len;
		if (noplen > ASM_NOP_MAX)
			noplen = ASM_NOP_MAX;
		memcpy(insns, x86_nops[noplen], noplen);
		insns += noplen;
		len -= noplen;
	}
}

extern s32 __retpoline_sites[], __retpoline_sites_end[];
extern s32 __return_sites[], __return_sites_end[];
extern s32 __ibt_endbr_seal[], __ibt_endbr_seal_end[];
extern struct alt_instr __alt_instructions[], __alt_instructions_end[];
extern s32 __smp_locks[], __smp_locks_end[];
void text_poke_early(void *addr, const void *opcode, size_t len);

static inline bool is_jmp(const u8 opcode)
{
	return opcode == 0xeb || opcode == 0xe9;
}

static void __init_or_module
recompute_jump(struct alt_instr *a, u8 *orig_insn, u8 *repl_insn, u8 *insn_buff)
{
	u8 *next_rip, *tgt_rip;
	s32 n_dspl, o_dspl;
	int repl_len;

	if (a->replacementlen != 5)
		return;

	o_dspl = *(s32 *)(insn_buff + 1);

	/* next_rip of the replacement JMP */
	next_rip = repl_insn + a->replacementlen;
	/* target rip of the replacement JMP */
	tgt_rip  = next_rip + o_dspl;
	n_dspl = tgt_rip - orig_insn;

	DPRINTK("target RIP: %px, new_displ: 0x%x", tgt_rip, n_dspl);

	if (tgt_rip - orig_insn >= 0) {
		if (n_dspl - 2 <= 127)
			goto two_byte_jmp;
		else
			goto five_byte_jmp;
	/* negative offset */
	} else {
		if (((n_dspl - 2) & 0xff) == (n_dspl - 2))
			goto two_byte_jmp;
		else
			goto five_byte_jmp;
	}

two_byte_jmp:
	n_dspl -= 2;

	insn_buff[0] = 0xeb;
	insn_buff[1] = (s8)n_dspl;
	add_nops(insn_buff + 2, 3);

	repl_len = 2;
	goto done;

five_byte_jmp:
	n_dspl -= 5;

	insn_buff[0] = 0xe9;

	repl_len = 5;

done:

	DPRINTK("final displ: 0x%08x, JMP 0x%lx",
		n_dspl, (unsigned long)orig_insn + n_dspl + repl_len);
}

static __always_inline int optimize_nops_range(u8 *instr, u8 instrlen, int off)
{
	unsigned long flags;
	int i = off, nnops;

	while (i < instrlen) {
		if (instr[i] != 0x90)
			break;

		i++;
	}

	nnops = i - off;

	if (nnops <= 1)
		return nnops;

	local_irq_save(flags);
	add_nops(instr + off, nnops);
	local_irq_restore(flags);

	DUMP_BYTES(instr, instrlen, "%px: [%d:%d) optimized NOPs: ", instr, off, i);

	return nnops;
}

static void __init_or_module noinline optimize_nops(u8 *instr, size_t len)
{
	struct insn insn;
	int i = 0;

	/*
	for (;;) {
		if (insn_decode_kernel(&insn, &instr[i]))
			return;

		/*
		if (insn.length == 1 && insn.opcode.bytes[0] == 0x90)
			i += optimize_nops_range(instr, len, i);
		else
			i += insn.length;

		if (i >= len)
			return;
	}
}

void __init_or_module noinline apply_alternatives(struct alt_instr *start,
						  struct alt_instr *end)
{
	struct alt_instr *a;
	u8 *instr, *replacement;
	u8 insn_buff[MAX_PATCH_LEN];

	DPRINTK("alt table %px, -> %px", start, end);
	/*
	for (a = start; a < end; a++) {
		int insn_buff_sz = 0;
		/* Mask away "NOT" flag bit for feature to test. */
		u16 feature = a->cpuid & ~ALTINSTR_FLAG_INV;

		instr = (u8 *)&a->instr_offset + a->instr_offset;
		replacement = (u8 *)&a->repl_offset + a->repl_offset;
		BUG_ON(a->instrlen > sizeof(insn_buff));
		BUG_ON(feature >= (NCAPINTS + NBUGINTS) * 32);

		/*
		if (!boot_cpu_has(feature) == !(a->cpuid & ALTINSTR_FLAG_INV))
			goto next;

		DPRINTK("feat: %s%d*32+%d, old: (%pS (%px) len: %d), repl: (%px, len: %d)",
			(a->cpuid & ALTINSTR_FLAG_INV) ? "!" : "",
			feature >> 5,
			feature & 0x1f,
			instr, instr, a->instrlen,
			replacement, a->replacementlen);

		DUMP_BYTES(instr, a->instrlen, "%px:   old_insn: ", instr);
		DUMP_BYTES(replacement, a->replacementlen, "%px:   rpl_insn: ", replacement);

		memcpy(insn_buff, replacement, a->replacementlen);
		insn_buff_sz = a->replacementlen;

		/*
		if (a->replacementlen == 5 && *insn_buff == 0xe8) {
			*(s32 *)(insn_buff + 1) += replacement - instr;
			DPRINTK("Fix CALL offset: 0x%x, CALL 0x%lx",
				*(s32 *)(insn_buff + 1),
				(unsigned long)instr + *(s32 *)(insn_buff + 1) + 5);
		}

		if (a->replacementlen && is_jmp(replacement[0]))
			recompute_jump(a, instr, replacement, insn_buff);

		for (; insn_buff_sz < a->instrlen; insn_buff_sz++)
			insn_buff[insn_buff_sz] = 0x90;

		DUMP_BYTES(insn_buff, insn_buff_sz, "%px: final_insn: ", instr);

		text_poke_early(instr, insn_buff, insn_buff_sz);

next:
		optimize_nops(instr, a->instrlen);
	}
}

#if defined(CONFIG_RETPOLINE) && defined(CONFIG_OBJTOOL)

static int emit_indirect(int op, int reg, u8 *bytes)
{
	int i = 0;
	u8 modrm;

	switch (op) {
	case CALL_INSN_OPCODE:
		modrm = 0x10; /* Reg = 2; CALL r/m */
		break;

	case JMP32_INSN_OPCODE:
		modrm = 0x20; /* Reg = 4; JMP r/m */
		break;

	default:
		WARN_ON_ONCE(1);
		return -1;
	}

	if (reg >= 8) {
		bytes[i++] = 0x41; /* REX.B prefix */
		reg -= 8;
	}

	modrm |= 0xc0; /* Mod = 3 */
	modrm += reg;

	bytes[i++] = 0xff; /* opcode */
	bytes[i++] = modrm;

	return i;
}

static int patch_retpoline(void *addr, struct insn *insn, u8 *bytes)
{
	retpoline_thunk_t *target;
	int reg, ret, i = 0;
	u8 op, cc;

	target = addr + insn->length + insn->immediate.value;
	reg = target - __x86_indirect_thunk_array;

	if (WARN_ON_ONCE(reg & ~0xf))
		return -1;

	/* If anyone ever does: CALL/JMP *%rsp, we're in deep trouble. */
	BUG_ON(reg == 4);

	if (cpu_feature_enabled(X86_FEATURE_RETPOLINE) &&
	    !cpu_feature_enabled(X86_FEATURE_RETPOLINE_LFENCE))
		return -1;

	op = insn->opcode.bytes[0];

	/*
	/* Jcc.d32 second opcode byte is in the range: 0x80-0x8f */
	if (op == 0x0f && (insn->opcode.bytes[1] & 0xf0) == 0x80) {
		cc = insn->opcode.bytes[1] & 0xf;
		cc ^= 1; /* invert condition */

		bytes[i++] = 0x70 + cc;        /* Jcc.d8 */
		bytes[i++] = insn->length - 2; /* sizeof(Jcc.d8) == 2 */

		/* Continue as if: JMP.d32 __x86_indirect_thunk_\reg */
		op = JMP32_INSN_OPCODE;
	}

	/*
	if (cpu_feature_enabled(X86_FEATURE_RETPOLINE_LFENCE)) {
		bytes[i++] = 0x0f;
		bytes[i++] = 0xae;
		bytes[i++] = 0xe8; /* LFENCE */
	}

	ret = emit_indirect(op, reg, bytes + i);
	if (ret < 0)
		return ret;
	i += ret;

	for (; i < insn->length;)
		bytes[i++] = BYTES_NOP1;

	return i;
}

void __init_or_module noinline apply_retpolines(s32 *start, s32 *end)
{
	s32 *s;

	for (s = start; s < end; s++) {
		void *addr = (void *)s + *s;
		struct insn insn;
		int len, ret;
		u8 bytes[16];
		u8 op1, op2;

		ret = insn_decode_kernel(&insn, addr);
		if (WARN_ON_ONCE(ret < 0))
			continue;

		op1 = insn.opcode.bytes[0];
		op2 = insn.opcode.bytes[1];

		switch (op1) {
		case CALL_INSN_OPCODE:
		case JMP32_INSN_OPCODE:
			break;

		case 0x0f: /* escape */
			if (op2 >= 0x80 && op2 <= 0x8f)
				break;
			fallthrough;
		default:
			WARN_ON_ONCE(1);
			continue;
		}

		DPRINTK("retpoline at: %pS (%px) len: %d to: %pS",
			addr, addr, insn.length,
			addr + insn.length + insn.immediate.value);

		len = patch_retpoline(addr, &insn, bytes);
		if (len == insn.length) {
			optimize_nops(bytes, len);
			DUMP_BYTES(((u8*)addr),  len, "%px: orig: ", addr);
			DUMP_BYTES(((u8*)bytes), len, "%px: repl: ", addr);
			text_poke_early(addr, bytes, len);
		}
	}
}

#ifdef CONFIG_RETHUNK
static int patch_return(void *addr, struct insn *insn, u8 *bytes)
{
	int i = 0;

	if (cpu_feature_enabled(X86_FEATURE_RETHUNK))
		return -1;

	bytes[i++] = RET_INSN_OPCODE;

	for (; i < insn->length;)
		bytes[i++] = INT3_INSN_OPCODE;

	return i;
}

void __init_or_module noinline apply_returns(s32 *start, s32 *end)
{
	s32 *s;

	for (s = start; s < end; s++) {
		void *dest = NULL, *addr = (void *)s + *s;
		struct insn insn;
		int len, ret;
		u8 bytes[16];
		u8 op;

		ret = insn_decode_kernel(&insn, addr);
		if (WARN_ON_ONCE(ret < 0))
			continue;

		op = insn.opcode.bytes[0];
		if (op == JMP32_INSN_OPCODE)
			dest = addr + insn.length + insn.immediate.value;

		if (__static_call_fixup(addr, op, dest) ||
		    WARN_ONCE(dest != &__x86_return_thunk,
			      "missing return thunk: %pS-%pS: %*ph",
			      addr, dest, 5, addr))
			continue;

		DPRINTK("return thunk at: %pS (%px) len: %d to: %pS",
			addr, addr, insn.length,
			addr + insn.length + insn.immediate.value);

		len = patch_return(addr, &insn, bytes);
		if (len == insn.length) {
			DUMP_BYTES(((u8*)addr),  len, "%px: orig: ", addr);
			DUMP_BYTES(((u8*)bytes), len, "%px: repl: ", addr);
			text_poke_early(addr, bytes, len);
		}
	}
}
#else
void __init_or_module noinline apply_returns(s32 *start, s32 *end) { }
#endif /* CONFIG_RETHUNK */

#else /* !CONFIG_RETPOLINE || !CONFIG_OBJTOOL */

void __init_or_module noinline apply_retpolines(s32 *start, s32 *end) { }
void __init_or_module noinline apply_returns(s32 *start, s32 *end) { }

#endif /* CONFIG_RETPOLINE && CONFIG_OBJTOOL */

#ifdef CONFIG_X86_KERNEL_IBT

void __init_or_module noinline apply_ibt_endbr(s32 *start, s32 *end)
{
	s32 *s;

	for (s = start; s < end; s++) {
		u32 endbr, poison = gen_endbr_poison();
		void *addr = (void *)s + *s;

		if (WARN_ON_ONCE(get_kernel_nofault(endbr, addr)))
			continue;

		if (WARN_ON_ONCE(!is_endbr(endbr)))
			continue;

		DPRINTK("ENDBR at: %pS (%px)", addr, addr);

		/*
		DUMP_BYTES(((u8*)addr), 4, "%px: orig: ", addr);
		DUMP_BYTES(((u8*)&poison), 4, "%px: repl: ", addr);
		text_poke_early(addr, &poison, 4);
	}
}

#else

void __init_or_module noinline apply_ibt_endbr(s32 *start, s32 *end) { }

#endif /* CONFIG_X86_KERNEL_IBT */

#ifdef CONFIG_SMP
static void alternatives_smp_lock(const s32 *start, const s32 *end,
				  u8 *text, u8 *text_end)
{
	const s32 *poff;

	for (poff = start; poff < end; poff++) {
		u8 *ptr = (u8 *)poff + *poff;

		if (!*poff || ptr < text || ptr >= text_end)
			continue;
		/* turn DS segment override prefix into lock prefix */
		if (*ptr == 0x3e)
			text_poke(ptr, ((unsigned char []){0xf0}), 1);
	}
}

static void alternatives_smp_unlock(const s32 *start, const s32 *end,
				    u8 *text, u8 *text_end)
{
	const s32 *poff;

	for (poff = start; poff < end; poff++) {
		u8 *ptr = (u8 *)poff + *poff;

		if (!*poff || ptr < text || ptr >= text_end)
			continue;
		/* turn lock prefix into DS segment override prefix */
		if (*ptr == 0xf0)
			text_poke(ptr, ((unsigned char []){0x3E}), 1);
	}
}

struct smp_alt_module {
	/* what is this ??? */
	struct module	*mod;
	char		*name;

	/* ptrs to lock prefixes */
	const s32	*locks;
	const s32	*locks_end;

	/* .text segment, needed to avoid patching init code ;) */
	u8		*text;
	u8		*text_end;

	struct list_head next;
};
static LIST_HEAD(smp_alt_modules);
static bool uniproc_patched = false;	/* protected by text_mutex */

void __init_or_module alternatives_smp_module_add(struct module *mod,
						  char *name,
						  void *locks, void *locks_end,
						  void *text,  void *text_end)
{
	struct smp_alt_module *smp;

	mutex_lock(&text_mutex);
	if (!uniproc_patched)
		goto unlock;

	if (num_possible_cpus() == 1)
		/* Don't bother remembering, we'll never have to undo it. */
		goto smp_unlock;

	smp = kzalloc(sizeof(*smp), GFP_KERNEL);
	if (NULL == smp)
		/* we'll run the (safe but slow) SMP code then ... */
		goto unlock;

	smp->mod	= mod;
	smp->name	= name;
	smp->locks	= locks;
	smp->locks_end	= locks_end;
	smp->text	= text;
	smp->text_end	= text_end;
	DPRINTK("locks %p -> %p, text %p -> %p, name %s\n",
		smp->locks, smp->locks_end,
		smp->text, smp->text_end, smp->name);

	list_add_tail(&smp->next, &smp_alt_modules);
smp_unlock:
	alternatives_smp_unlock(locks, locks_end, text, text_end);
unlock:
	mutex_unlock(&text_mutex);
}

void __init_or_module alternatives_smp_module_del(struct module *mod)
{
	struct smp_alt_module *item;

	mutex_lock(&text_mutex);
	list_for_each_entry(item, &smp_alt_modules, next) {
		if (mod != item->mod)
			continue;
		list_del(&item->next);
		kfree(item);
		break;
	}
	mutex_unlock(&text_mutex);
}

void alternatives_enable_smp(void)
{
	struct smp_alt_module *mod;

	/* Why bother if there are no other CPUs? */
	BUG_ON(num_possible_cpus() == 1);

	mutex_lock(&text_mutex);

	if (uniproc_patched) {
		pr_info("switching to SMP code\n");
		BUG_ON(num_online_cpus() != 1);
		clear_cpu_cap(&boot_cpu_data, X86_FEATURE_UP);
		clear_cpu_cap(&cpu_data(0), X86_FEATURE_UP);
		list_for_each_entry(mod, &smp_alt_modules, next)
			alternatives_smp_lock(mod->locks, mod->locks_end,
					      mod->text, mod->text_end);
		uniproc_patched = false;
	}
	mutex_unlock(&text_mutex);
}

int alternatives_text_reserved(void *start, void *end)
{
	struct smp_alt_module *mod;
	const s32 *poff;
	u8 *text_start = start;
	u8 *text_end = end;

	lockdep_assert_held(&text_mutex);

	list_for_each_entry(mod, &smp_alt_modules, next) {
		if (mod->text > text_end || mod->text_end < text_start)
			continue;
		for (poff = mod->locks; poff < mod->locks_end; poff++) {
			const u8 *ptr = (const u8 *)poff + *poff;

			if (text_start <= ptr && text_end > ptr)
				return 1;
		}
	}

	return 0;
}
#endif /* CONFIG_SMP */

#ifdef CONFIG_PARAVIRT
void __init_or_module apply_paravirt(struct paravirt_patch_site *start,
				     struct paravirt_patch_site *end)
{
	struct paravirt_patch_site *p;
	char insn_buff[MAX_PATCH_LEN];

	for (p = start; p < end; p++) {
		unsigned int used;

		BUG_ON(p->len > MAX_PATCH_LEN);
		/* prep the buffer with the original instructions */
		memcpy(insn_buff, p->instr, p->len);
		used = paravirt_patch(p->type, insn_buff, (unsigned long)p->instr, p->len);

		BUG_ON(used > p->len);

		/* Pad the rest with nops */
		add_nops(insn_buff + used, p->len - used);
		text_poke_early(p->instr, insn_buff, p->len);
	}
}
extern struct paravirt_patch_site __start_parainstructions[],
	__stop_parainstructions[];
#endif	/* CONFIG_PARAVIRT */



extern void int3_magic(unsigned int *ptr); /* defined in asm */

asm (
"	.pushsection	.init.text, \"ax\", @progbits\n"
"	.type		int3_magic, @function\n"
"int3_magic:\n"
	ANNOTATE_NOENDBR
"	movl	$1, (%" _ASM_ARG1 ")\n"
	ASM_RET
"	.size		int3_magic, .-int3_magic\n"
"	.popsection\n"
);

extern void int3_selftest_ip(void); /* defined in asm below */

static int __init
int3_exception_notify(struct notifier_block *self, unsigned long val, void *data)
{
	unsigned long selftest = (unsigned long)&int3_selftest_ip;
	struct die_args *args = data;
	struct pt_regs *regs = args->regs;

	OPTIMIZER_HIDE_VAR(selftest);

	if (!regs || user_mode(regs))
		return NOTIFY_DONE;

	if (val != DIE_INT3)
		return NOTIFY_DONE;

	if (regs->ip - INT3_INSN_SIZE != selftest)
		return NOTIFY_DONE;

	int3_emulate_call(regs, (unsigned long)&int3_magic);
	return NOTIFY_STOP;
}

static noinline void __init int3_selftest(void)
{
	static __initdata struct notifier_block int3_exception_nb = {
		.notifier_call	= int3_exception_notify,
		.priority	= INT_MAX-1, /* last */
	};
	unsigned int val = 0;

	BUG_ON(register_die_notifier(&int3_exception_nb));

	/*
	asm volatile ("int3_selftest_ip:\n\t"
		      ANNOTATE_NOENDBR
		      "    int3; nop; nop; nop; nop\n\t"
		      : ASM_CALL_CONSTRAINT
		      : __ASM_SEL_RAW(a, D) (&val)
		      : "memory");

	BUG_ON(val != 1);

	unregister_die_notifier(&int3_exception_nb);
}

void __init alternative_instructions(void)
{
	int3_selftest();

	/*
	stop_nmi();

	/*

	/*
	paravirt_set_cap();

	/*
	apply_paravirt(__parainstructions, __parainstructions_end);

	/*
	apply_retpolines(__retpoline_sites, __retpoline_sites_end);
	apply_returns(__return_sites, __return_sites_end);

	/*
	apply_alternatives(__alt_instructions, __alt_instructions_end);

	apply_ibt_endbr(__ibt_endbr_seal, __ibt_endbr_seal_end);

#ifdef CONFIG_SMP
	/* Patch to UP if other cpus not imminent. */
	if (!noreplace_smp && (num_present_cpus() == 1 || setup_max_cpus <= 1)) {
		uniproc_patched = true;
		alternatives_smp_module_add(NULL, "core kernel",
					    __smp_locks, __smp_locks_end,
					    _text, _etext);
	}

	if (!uniproc_patched || num_possible_cpus() == 1) {
		free_init_pages("SMP alternatives",
				(unsigned long)__smp_locks,
				(unsigned long)__smp_locks_end);
	}
#endif

	restart_nmi();
	alternatives_patched = 1;
}

void __init_or_module text_poke_early(void *addr, const void *opcode,
				      size_t len)
{
	unsigned long flags;

	if (boot_cpu_has(X86_FEATURE_NX) &&
	    is_module_text_address((unsigned long)addr)) {
		/*
		memcpy(addr, opcode, len);
	} else {
		local_irq_save(flags);
		memcpy(addr, opcode, len);
		local_irq_restore(flags);
		sync_core();

		/*
	}
}

typedef struct {
	struct mm_struct *mm;
} temp_mm_state_t;

static inline temp_mm_state_t use_temporary_mm(struct mm_struct *mm)
{
	temp_mm_state_t temp_state;

	lockdep_assert_irqs_disabled();

	/*
	if (this_cpu_read(cpu_tlbstate_shared.is_lazy))
		leave_mm(smp_processor_id());

	temp_state.mm = this_cpu_read(cpu_tlbstate.loaded_mm);
	switch_mm_irqs_off(NULL, mm, current);

	/*
	if (hw_breakpoint_active())
		hw_breakpoint_disable();

	return temp_state;
}

static inline void unuse_temporary_mm(temp_mm_state_t prev_state)
{
	lockdep_assert_irqs_disabled();
	switch_mm_irqs_off(NULL, prev_state.mm, current);

	/*
	if (hw_breakpoint_active())
		hw_breakpoint_restore();
}

__ro_after_init struct mm_struct *poking_mm;
__ro_after_init unsigned long poking_addr;

static void text_poke_memcpy(void *dst, const void *src, size_t len)
{
	memcpy(dst, src, len);
}

static void text_poke_memset(void *dst, const void *src, size_t len)
{
	int c = *(const int *)src;

	memset(dst, c, len);
}

typedef void text_poke_f(void *dst, const void *src, size_t len);

static void *__text_poke(text_poke_f func, void *addr, const void *src, size_t len)
{
	bool cross_page_boundary = offset_in_page(addr) + len > PAGE_SIZE;
	struct page *pages[2] = {NULL};
	temp_mm_state_t prev;
	unsigned long flags;
	pte_t pte, *ptep;
	spinlock_t *ptl;
	pgprot_t pgprot;

	/*
	BUG_ON(!after_bootmem);

	if (!core_kernel_text((unsigned long)addr)) {
		pages[0] = vmalloc_to_page(addr);
		if (cross_page_boundary)
			pages[1] = vmalloc_to_page(addr + PAGE_SIZE);
	} else {
		pages[0] = virt_to_page(addr);
		WARN_ON(!PageReserved(pages[0]));
		if (cross_page_boundary)
			pages[1] = virt_to_page(addr + PAGE_SIZE);
	}
	/*
	BUG_ON(!pages[0] || (cross_page_boundary && !pages[1]));

	/*
	pgprot = __pgprot(pgprot_val(PAGE_KERNEL) & ~_PAGE_GLOBAL);

	/*
	ptep = get_locked_pte(poking_mm, poking_addr, &ptl);

	/*
	VM_BUG_ON(!ptep);

	local_irq_save(flags);

	pte = mk_pte(pages[0], pgprot);
	set_pte_at(poking_mm, poking_addr, ptep, pte);

	if (cross_page_boundary) {
		pte = mk_pte(pages[1], pgprot);
		set_pte_at(poking_mm, poking_addr + PAGE_SIZE, ptep + 1, pte);
	}

	/*
	prev = use_temporary_mm(poking_mm);

	kasan_disable_current();
	func((u8 *)poking_addr + offset_in_page(addr), src, len);
	kasan_enable_current();

	/*
	barrier();

	pte_clear(poking_mm, poking_addr, ptep);
	if (cross_page_boundary)
		pte_clear(poking_mm, poking_addr + PAGE_SIZE, ptep + 1);

	/*
	unuse_temporary_mm(prev);

	/*
	flush_tlb_mm_range(poking_mm, poking_addr, poking_addr +
			   (cross_page_boundary ? 2 : 1) * PAGE_SIZE,
			   PAGE_SHIFT, false);

	if (func == text_poke_memcpy) {
		/*
		BUG_ON(memcmp(addr, src, len));
	}

	local_irq_restore(flags);
	pte_unmap_unlock(ptep, ptl);
	return addr;
}

void *text_poke(void *addr, const void *opcode, size_t len)
{
	lockdep_assert_held(&text_mutex);

	return __text_poke(text_poke_memcpy, addr, opcode, len);
}

void *text_poke_kgdb(void *addr, const void *opcode, size_t len)
{
	return __text_poke(text_poke_memcpy, addr, opcode, len);
}

void *text_poke_copy(void *addr, const void *opcode, size_t len)
{
	unsigned long start = (unsigned long)addr;
	size_t patched = 0;

	if (WARN_ON_ONCE(core_kernel_text(start)))
		return NULL;

	mutex_lock(&text_mutex);
	while (patched < len) {
		unsigned long ptr = start + patched;
		size_t s;

		s = min_t(size_t, PAGE_SIZE * 2 - offset_in_page(ptr), len - patched);

		__text_poke(text_poke_memcpy, (void *)ptr, opcode + patched, s);
		patched += s;
	}
	mutex_unlock(&text_mutex);
	return addr;
}

void *text_poke_set(void *addr, int c, size_t len)
{
	unsigned long start = (unsigned long)addr;
	size_t patched = 0;

	if (WARN_ON_ONCE(core_kernel_text(start)))
		return NULL;

	mutex_lock(&text_mutex);
	while (patched < len) {
		unsigned long ptr = start + patched;
		size_t s;

		s = min_t(size_t, PAGE_SIZE * 2 - offset_in_page(ptr), len - patched);

		__text_poke(text_poke_memset, (void *)ptr, (void *)&c, s);
		patched += s;
	}
	mutex_unlock(&text_mutex);
	return addr;
}

static void do_sync_core(void *info)
{
	sync_core();
}

void text_poke_sync(void)
{
	on_each_cpu(do_sync_core, NULL, 1);
}

struct text_poke_loc {
	/* addr := _stext + rel_addr */
	s32 rel_addr;
	s32 disp;
	u8 len;
	u8 opcode;
	const u8 text[POKE_MAX_OPCODE_SIZE];
	/* see text_poke_bp_batch() */
	u8 old;
};

struct bp_patching_desc {
	struct text_poke_loc *vec;
	int nr_entries;
	atomic_t refs;
};

static struct bp_patching_desc *bp_desc;

static __always_inline
struct bp_patching_desc *try_get_desc(struct bp_patching_desc **descp)
{
	/* rcu_dereference */
	struct bp_patching_desc *desc = __READ_ONCE(*descp);

	if (!desc || !arch_atomic_inc_not_zero(&desc->refs))
		return NULL;

	return desc;
}

static __always_inline void put_desc(struct bp_patching_desc *desc)
{
	smp_mb__before_atomic();
	arch_atomic_dec(&desc->refs);
}

static __always_inline void *text_poke_addr(struct text_poke_loc *tp)
{
	return _stext + tp->rel_addr;
}

static __always_inline int patch_cmp(const void *key, const void *elt)
{
	struct text_poke_loc *tp = (struct text_poke_loc *) elt;

	if (key < text_poke_addr(tp))
		return -1;
	if (key > text_poke_addr(tp))
		return 1;
	return 0;
}

noinstr int poke_int3_handler(struct pt_regs *regs)
{
	struct bp_patching_desc *desc;
	struct text_poke_loc *tp;
	int ret = 0;
	void *ip;

	if (user_mode(regs))
		return 0;

	/*
	smp_rmb();

	desc = try_get_desc(&bp_desc);
	if (!desc)
		return 0;

	/*
	ip = (void *) regs->ip - INT3_INSN_SIZE;

	/*
	if (unlikely(desc->nr_entries > 1)) {
		tp = __inline_bsearch(ip, desc->vec, desc->nr_entries,
				      sizeof(struct text_poke_loc),
				      patch_cmp);
		if (!tp)
			goto out_put;
	} else {
		tp = desc->vec;
		if (text_poke_addr(tp) != ip)
			goto out_put;
	}

	ip += tp->len;

	switch (tp->opcode) {
	case INT3_INSN_OPCODE:
		/*
		goto out_put;

	case RET_INSN_OPCODE:
		int3_emulate_ret(regs);
		break;

	case CALL_INSN_OPCODE:
		int3_emulate_call(regs, (long)ip + tp->disp);
		break;

	case JMP32_INSN_OPCODE:
	case JMP8_INSN_OPCODE:
		int3_emulate_jmp(regs, (long)ip + tp->disp);
		break;

	default:
		BUG();
	}

	ret = 1;

out_put:
	put_desc(desc);
	return ret;
}

#define TP_VEC_MAX (PAGE_SIZE / sizeof(struct text_poke_loc))
static struct text_poke_loc tp_vec[TP_VEC_MAX];
static int tp_vec_nr;

static void text_poke_bp_batch(struct text_poke_loc *tp, unsigned int nr_entries)
{
	struct bp_patching_desc desc = {
		.vec = tp,
		.nr_entries = nr_entries,
		.refs = ATOMIC_INIT(1),
	};
	unsigned char int3 = INT3_INSN_OPCODE;
	unsigned int i;
	int do_sync;

	lockdep_assert_held(&text_mutex);

	smp_store_release(&bp_desc, &desc); /* rcu_assign_pointer */

	/*
	smp_wmb();

	/*
	for (i = 0; i < nr_entries; i++) {
		tp[i].old = *(u8 *)text_poke_addr(&tp[i]);
		text_poke(text_poke_addr(&tp[i]), &int3, INT3_INSN_SIZE);
	}

	text_poke_sync();

	/*
	for (do_sync = 0, i = 0; i < nr_entries; i++) {
		u8 old[POKE_MAX_OPCODE_SIZE] = { tp[i].old, };
		int len = tp[i].len;

		if (len - INT3_INSN_SIZE > 0) {
			memcpy(old + INT3_INSN_SIZE,
			       text_poke_addr(&tp[i]) + INT3_INSN_SIZE,
			       len - INT3_INSN_SIZE);
			text_poke(text_poke_addr(&tp[i]) + INT3_INSN_SIZE,
				  (const char *)tp[i].text + INT3_INSN_SIZE,
				  len - INT3_INSN_SIZE);
			do_sync++;
		}

		/*
		perf_event_text_poke(text_poke_addr(&tp[i]), old, len,
				     tp[i].text, len);
	}

	if (do_sync) {
		/*
		text_poke_sync();
	}

	/*
	for (do_sync = 0, i = 0; i < nr_entries; i++) {
		if (tp[i].text[0] == INT3_INSN_OPCODE)
			continue;

		text_poke(text_poke_addr(&tp[i]), tp[i].text, INT3_INSN_SIZE);
		do_sync++;
	}

	if (do_sync)
		text_poke_sync();

	/*
	WRITE_ONCE(bp_desc, NULL); /* RCU_INIT_POINTER */
	if (!atomic_dec_and_test(&desc.refs))
		atomic_cond_read_acquire(&desc.refs, !VAL);
}

static void text_poke_loc_init(struct text_poke_loc *tp, void *addr,
			       const void *opcode, size_t len, const void *emulate)
{
	struct insn insn;
	int ret, i;

	memcpy((void *)tp->text, opcode, len);
	if (!emulate)
		emulate = opcode;

	ret = insn_decode_kernel(&insn, emulate);
	BUG_ON(ret < 0);

	tp->rel_addr = addr - (void *)_stext;
	tp->len = len;
	tp->opcode = insn.opcode.bytes[0];

	switch (tp->opcode) {
	case RET_INSN_OPCODE:
	case JMP32_INSN_OPCODE:
	case JMP8_INSN_OPCODE:
		/*
		for (i = insn.length; i < len; i++)
			BUG_ON(tp->text[i] != INT3_INSN_OPCODE);
		break;

	default:
		BUG_ON(len != insn.length);
	};


	switch (tp->opcode) {
	case INT3_INSN_OPCODE:
	case RET_INSN_OPCODE:
		break;

	case CALL_INSN_OPCODE:
	case JMP32_INSN_OPCODE:
	case JMP8_INSN_OPCODE:
		tp->disp = insn.immediate.value;
		break;

	default: /* assume NOP */
		switch (len) {
		case 2: /* NOP2 -- emulate as JMP8+0 */
			BUG_ON(memcmp(emulate, x86_nops[len], len));
			tp->opcode = JMP8_INSN_OPCODE;
			tp->disp = 0;
			break;

		case 5: /* NOP5 -- emulate as JMP32+0 */
			BUG_ON(memcmp(emulate, x86_nops[len], len));
			tp->opcode = JMP32_INSN_OPCODE;
			tp->disp = 0;
			break;

		default: /* unknown instruction */
			BUG();
		}
		break;
	}
}

static bool tp_order_fail(void *addr)
{
	struct text_poke_loc *tp;

	if (!tp_vec_nr)
		return false;

	if (!addr) /* force */
		return true;

	tp = &tp_vec[tp_vec_nr - 1];
	if ((unsigned long)text_poke_addr(tp) > (unsigned long)addr)
		return true;

	return false;
}

static void text_poke_flush(void *addr)
{
	if (tp_vec_nr == TP_VEC_MAX || tp_order_fail(addr)) {
		text_poke_bp_batch(tp_vec, tp_vec_nr);
		tp_vec_nr = 0;
	}
}

void text_poke_finish(void)
{
	text_poke_flush(NULL);
}

void __ref text_poke_queue(void *addr, const void *opcode, size_t len, const void *emulate)
{
	struct text_poke_loc *tp;

	if (unlikely(system_state == SYSTEM_BOOTING)) {
		text_poke_early(addr, opcode, len);
		return;
	}

	text_poke_flush(addr);

	tp = &tp_vec[tp_vec_nr++];
	text_poke_loc_init(tp, addr, opcode, len, emulate);
}

void __ref text_poke_bp(void *addr, const void *opcode, size_t len, const void *emulate)
{
	struct text_poke_loc tp;

	if (unlikely(system_state == SYSTEM_BOOTING)) {
		text_poke_early(addr, opcode, len);
		return;
	}

	text_poke_loc_init(&tp, addr, opcode, len, emulate);
	text_poke_bp_batch(&tp, 1);
}
