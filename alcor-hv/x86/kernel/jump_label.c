#include <linux/jump_label.h>
#include <linux/memory.h>
#include <linux/uaccess.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/jhash.h>
#include <linux/cpu.h>
#include <asm/kprobes.h>
#include <asm/alternative.h>
#include <asm/text-patching.h>
#include <asm/insn.h>

int arch_jump_entry_size(struct jump_entry *entry)
{
	struct insn insn = {};

	insn_decode_kernel(&insn, (void *)jump_entry_code(entry));
	BUG_ON(insn.length != 2 && insn.length != 5);

	return insn.length;
}

struct jump_label_patch {
	const void *code;
	int size;
};

static struct jump_label_patch
__jump_label_patch(struct jump_entry *entry, enum jump_label_type type)
{
	const void *expect, *code, *nop;
	const void *addr, *dest;
	int size;

	addr = (void *)jump_entry_code(entry);
	dest = (void *)jump_entry_target(entry);

	size = arch_jump_entry_size(entry);
	switch (size) {
	case JMP8_INSN_SIZE:
		code = text_gen_insn(JMP8_INSN_OPCODE, addr, dest);
		nop = x86_nops[size];
		break;

	case JMP32_INSN_SIZE:
		code = text_gen_insn(JMP32_INSN_OPCODE, addr, dest);
		nop = x86_nops[size];
		break;

	default: BUG();
	}

	if (type == JUMP_LABEL_JMP)
		expect = nop;
	else
		expect = code;

	if (memcmp(addr, expect, size)) {
		/*
		pr_crit("jump_label: Fatal kernel bug, unexpected op at %pS [%p] (%5ph != %5ph)) size:%d type:%d\n",
				addr, addr, addr, expect, size, type);
		BUG();
	}

	if (type == JUMP_LABEL_NOP)
		code = nop;

	return (struct jump_label_patch){.code = code, .size = size};
}

static __always_inline void
__jump_label_transform(struct jump_entry *entry,
		       enum jump_label_type type,
		       int init)
{
	const struct jump_label_patch jlp = __jump_label_patch(entry, type);

	/*
	if (init || system_state == SYSTEM_BOOTING) {
		text_poke_early((void *)jump_entry_code(entry), jlp.code, jlp.size);
		return;
	}

	text_poke_bp((void *)jump_entry_code(entry), jlp.code, jlp.size, NULL);
}

static void __ref jump_label_transform(struct jump_entry *entry,
				       enum jump_label_type type,
				       int init)
{
	mutex_lock(&text_mutex);
	__jump_label_transform(entry, type, init);
	mutex_unlock(&text_mutex);
}

void arch_jump_label_transform(struct jump_entry *entry,
			       enum jump_label_type type)
{
	jump_label_transform(entry, type, 0);
}

bool arch_jump_label_transform_queue(struct jump_entry *entry,
				     enum jump_label_type type)
{
	struct jump_label_patch jlp;

	if (system_state == SYSTEM_BOOTING) {
		/*
		arch_jump_label_transform(entry, type);
		return true;
	}

	mutex_lock(&text_mutex);
	jlp = __jump_label_patch(entry, type);
	text_poke_queue((void *)jump_entry_code(entry), jlp.code, jlp.size, NULL);
	mutex_unlock(&text_mutex);
	return true;
}

void arch_jump_label_transform_apply(void)
{
	mutex_lock(&text_mutex);
	text_poke_finish();
	mutex_unlock(&text_mutex);
}
