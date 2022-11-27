
#include <linux/kernel.h>
#ifdef __KERNEL__
#include <linux/string.h>
#else
#include <string.h>
#endif
#include <asm/inat.h> /*__ignore_sync_check__ */
#include <asm/insn.h> /* __ignore_sync_check__ */
#include <asm/unaligned.h> /* __ignore_sync_check__ */

#include <linux/errno.h>
#include <linux/kconfig.h>

#include <asm/emulate_prefix.h> /* __ignore_sync_check__ */

#define leXX_to_cpu(t, r)						\
({									\
	__typeof__(t) v;						\
	switch (sizeof(t)) {						\
	case 4: v = le32_to_cpu(r); break;				\
	case 2: v = le16_to_cpu(r); break;				\
	case 1:	v = r; break;						\
	default:							\
		BUILD_BUG(); break;					\
	}								\
	v;								\
})

#define validate_next(t, insn, n)	\
	((insn)->next_byte + sizeof(t) + n <= (insn)->end_kaddr)

#define __get_next(t, insn)	\
	({ t r = get_unaligned((t *)(insn)->next_byte); (insn)->next_byte += sizeof(t); leXX_to_cpu(t, r); })

#define __peek_nbyte_next(t, insn, n)	\
	({ t r = get_unaligned((t *)(insn)->next_byte + n); leXX_to_cpu(t, r); })

#define get_next(t, insn)	\
	({ if (unlikely(!validate_next(t, insn, 0))) goto err_out; __get_next(t, insn); })

#define peek_nbyte_next(t, insn, n)	\
	({ if (unlikely(!validate_next(t, insn, n))) goto err_out; __peek_nbyte_next(t, insn, n); })

#define peek_next(t, insn)	peek_nbyte_next(t, insn, 0)

void insn_init(struct insn *insn, const void *kaddr, int buf_len, int x86_64)
{
	/*
	if (buf_len > MAX_INSN_SIZE)
		buf_len = MAX_INSN_SIZE;

	memset(insn, 0, sizeof(*insn));
	insn->kaddr = kaddr;
	insn->end_kaddr = kaddr + buf_len;
	insn->next_byte = kaddr;
	insn->x86_64 = x86_64 ? 1 : 0;
	insn->opnd_bytes = 4;
	if (x86_64)
		insn->addr_bytes = 8;
	else
		insn->addr_bytes = 4;
}

static const insn_byte_t xen_prefix[] = { __XEN_EMULATE_PREFIX };
static const insn_byte_t kvm_prefix[] = { __KVM_EMULATE_PREFIX };

static int __insn_get_emulate_prefix(struct insn *insn,
				     const insn_byte_t *prefix, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++) {
		if (peek_nbyte_next(insn_byte_t, insn, i) != prefix[i])
			goto err_out;
	}

	insn->emulate_prefix_size = len;
	insn->next_byte += len;

	return 1;

err_out:
	return 0;
}

static void insn_get_emulate_prefix(struct insn *insn)
{
	if (__insn_get_emulate_prefix(insn, xen_prefix, sizeof(xen_prefix)))
		return;

	__insn_get_emulate_prefix(insn, kvm_prefix, sizeof(kvm_prefix));
}

int insn_get_prefixes(struct insn *insn)
{
	struct insn_field *prefixes = &insn->prefixes;
	insn_attr_t attr;
	insn_byte_t b, lb;
	int i, nb;

	if (prefixes->got)
		return 0;

	insn_get_emulate_prefix(insn);

	nb = 0;
	lb = 0;
	b = peek_next(insn_byte_t, insn);
	attr = inat_get_opcode_attribute(b);
	while (inat_is_legacy_prefix(attr)) {
		/* Skip if same prefix */
		for (i = 0; i < nb; i++)
			if (prefixes->bytes[i] == b)
				goto found;
		if (nb == 4)
			/* Invalid instruction */
			break;
		prefixes->bytes[nb++] = b;
		if (inat_is_address_size_prefix(attr)) {
			/* address size switches 2/4 or 4/8 */
			if (insn->x86_64)
				insn->addr_bytes ^= 12;
			else
				insn->addr_bytes ^= 6;
		} else if (inat_is_operand_size_prefix(attr)) {
			/* oprand size switches 2/4 */
			insn->opnd_bytes ^= 6;
		}
found:
		prefixes->nbytes++;
		insn->next_byte++;
		lb = b;
		b = peek_next(insn_byte_t, insn);
		attr = inat_get_opcode_attribute(b);
	}
	/* Set the last prefix */
	if (lb && lb != insn->prefixes.bytes[3]) {
		if (unlikely(insn->prefixes.bytes[3])) {
			/* Swap the last prefix */
			b = insn->prefixes.bytes[3];
			for (i = 0; i < nb; i++)
				if (prefixes->bytes[i] == lb)
					insn_set_byte(prefixes, i, b);
		}
		insn_set_byte(&insn->prefixes, 3, lb);
	}

	/* Decode REX prefix */
	if (insn->x86_64) {
		b = peek_next(insn_byte_t, insn);
		attr = inat_get_opcode_attribute(b);
		if (inat_is_rex_prefix(attr)) {
			insn_field_set(&insn->rex_prefix, b, 1);
			insn->next_byte++;
			if (X86_REX_W(b))
				/* REX.W overrides opnd_size */
				insn->opnd_bytes = 8;
		}
	}
	insn->rex_prefix.got = 1;

	/* Decode VEX prefix */
	b = peek_next(insn_byte_t, insn);
	attr = inat_get_opcode_attribute(b);
	if (inat_is_vex_prefix(attr)) {
		insn_byte_t b2 = peek_nbyte_next(insn_byte_t, insn, 1);
		if (!insn->x86_64) {
			/*
			if (X86_MODRM_MOD(b2) != 3)
				goto vex_end;
		}
		insn_set_byte(&insn->vex_prefix, 0, b);
		insn_set_byte(&insn->vex_prefix, 1, b2);
		if (inat_is_evex_prefix(attr)) {
			b2 = peek_nbyte_next(insn_byte_t, insn, 2);
			insn_set_byte(&insn->vex_prefix, 2, b2);
			b2 = peek_nbyte_next(insn_byte_t, insn, 3);
			insn_set_byte(&insn->vex_prefix, 3, b2);
			insn->vex_prefix.nbytes = 4;
			insn->next_byte += 4;
			if (insn->x86_64 && X86_VEX_W(b2))
				/* VEX.W overrides opnd_size */
				insn->opnd_bytes = 8;
		} else if (inat_is_vex3_prefix(attr)) {
			b2 = peek_nbyte_next(insn_byte_t, insn, 2);
			insn_set_byte(&insn->vex_prefix, 2, b2);
			insn->vex_prefix.nbytes = 3;
			insn->next_byte += 3;
			if (insn->x86_64 && X86_VEX_W(b2))
				/* VEX.W overrides opnd_size */
				insn->opnd_bytes = 8;
		} else {
			/*
			insn_set_byte(&insn->vex_prefix, 2, b2 & 0x7f);
			insn->vex_prefix.nbytes = 2;
			insn->next_byte += 2;
		}
	}
vex_end:
	insn->vex_prefix.got = 1;

	prefixes->got = 1;

	return 0;

err_out:
	return -ENODATA;
}

int insn_get_opcode(struct insn *insn)
{
	struct insn_field *opcode = &insn->opcode;
	int pfx_id, ret;
	insn_byte_t op;

	if (opcode->got)
		return 0;

	if (!insn->prefixes.got) {
		ret = insn_get_prefixes(insn);
		if (ret)
			return ret;
	}

	/* Get first opcode */
	op = get_next(insn_byte_t, insn);
	insn_set_byte(opcode, 0, op);
	opcode->nbytes = 1;

	/* Check if there is VEX prefix or not */
	if (insn_is_avx(insn)) {
		insn_byte_t m, p;
		m = insn_vex_m_bits(insn);
		p = insn_vex_p_bits(insn);
		insn->attr = inat_get_avx_attribute(op, m, p);
		if ((inat_must_evex(insn->attr) && !insn_is_evex(insn)) ||
		    (!inat_accept_vex(insn->attr) &&
		     !inat_is_group(insn->attr))) {
			/* This instruction is bad */
			insn->attr = 0;
			return -EINVAL;
		}
		/* VEX has only 1 byte for opcode */
		goto end;
	}

	insn->attr = inat_get_opcode_attribute(op);
	while (inat_is_escape(insn->attr)) {
		/* Get escaped opcode */
		op = get_next(insn_byte_t, insn);
		opcode->bytes[opcode->nbytes++] = op;
		pfx_id = insn_last_prefix_id(insn);
		insn->attr = inat_get_escape_attribute(op, pfx_id, insn->attr);
	}

	if (inat_must_vex(insn->attr)) {
		/* This instruction is bad */
		insn->attr = 0;
		return -EINVAL;
	}
end:
	opcode->got = 1;
	return 0;

err_out:
	return -ENODATA;
}

int insn_get_modrm(struct insn *insn)
{
	struct insn_field *modrm = &insn->modrm;
	insn_byte_t pfx_id, mod;
	int ret;

	if (modrm->got)
		return 0;

	if (!insn->opcode.got) {
		ret = insn_get_opcode(insn);
		if (ret)
			return ret;
	}

	if (inat_has_modrm(insn->attr)) {
		mod = get_next(insn_byte_t, insn);
		insn_field_set(modrm, mod, 1);
		if (inat_is_group(insn->attr)) {
			pfx_id = insn_last_prefix_id(insn);
			insn->attr = inat_get_group_attribute(mod, pfx_id,
							      insn->attr);
			if (insn_is_avx(insn) && !inat_accept_vex(insn->attr)) {
				/* Bad insn */
				insn->attr = 0;
				return -EINVAL;
			}
		}
	}

	if (insn->x86_64 && inat_is_force64(insn->attr))
		insn->opnd_bytes = 8;

	modrm->got = 1;
	return 0;

err_out:
	return -ENODATA;
}


int insn_rip_relative(struct insn *insn)
{
	struct insn_field *modrm = &insn->modrm;
	int ret;

	if (!insn->x86_64)
		return 0;

	if (!modrm->got) {
		ret = insn_get_modrm(insn);
		if (ret)
			return 0;
	}
	/*
	return (modrm->nbytes && (modrm->bytes[0] & 0xc7) == 0x5);
}

int insn_get_sib(struct insn *insn)
{
	insn_byte_t modrm;
	int ret;

	if (insn->sib.got)
		return 0;

	if (!insn->modrm.got) {
		ret = insn_get_modrm(insn);
		if (ret)
			return ret;
	}

	if (insn->modrm.nbytes) {
		modrm = insn->modrm.bytes[0];
		if (insn->addr_bytes != 2 &&
		    X86_MODRM_MOD(modrm) != 3 && X86_MODRM_RM(modrm) == 4) {
			insn_field_set(&insn->sib,
				       get_next(insn_byte_t, insn), 1);
		}
	}
	insn->sib.got = 1;

	return 0;

err_out:
	return -ENODATA;
}


int insn_get_displacement(struct insn *insn)
{
	insn_byte_t mod, rm, base;
	int ret;

	if (insn->displacement.got)
		return 0;

	if (!insn->sib.got) {
		ret = insn_get_sib(insn);
		if (ret)
			return ret;
	}

	if (insn->modrm.nbytes) {
		/*
		mod = X86_MODRM_MOD(insn->modrm.value);
		rm = X86_MODRM_RM(insn->modrm.value);
		base = X86_SIB_BASE(insn->sib.value);
		if (mod == 3)
			goto out;
		if (mod == 1) {
			insn_field_set(&insn->displacement,
				       get_next(signed char, insn), 1);
		} else if (insn->addr_bytes == 2) {
			if ((mod == 0 && rm == 6) || mod == 2) {
				insn_field_set(&insn->displacement,
					       get_next(short, insn), 2);
			}
		} else {
			if ((mod == 0 && rm == 5) || mod == 2 ||
			    (mod == 0 && base == 5)) {
				insn_field_set(&insn->displacement,
					       get_next(int, insn), 4);
			}
		}
	}
out:
	insn->displacement.got = 1;
	return 0;

err_out:
	return -ENODATA;
}

static int __get_moffset(struct insn *insn)
{
	switch (insn->addr_bytes) {
	case 2:
		insn_field_set(&insn->moffset1, get_next(short, insn), 2);
		break;
	case 4:
		insn_field_set(&insn->moffset1, get_next(int, insn), 4);
		break;
	case 8:
		insn_field_set(&insn->moffset1, get_next(int, insn), 4);
		insn_field_set(&insn->moffset2, get_next(int, insn), 4);
		break;
	default:	/* opnd_bytes must be modified manually */
		goto err_out;
	}
	insn->moffset1.got = insn->moffset2.got = 1;

	return 1;

err_out:
	return 0;
}

static int __get_immv32(struct insn *insn)
{
	switch (insn->opnd_bytes) {
	case 2:
		insn_field_set(&insn->immediate, get_next(short, insn), 2);
		break;
	case 4:
	case 8:
		insn_field_set(&insn->immediate, get_next(int, insn), 4);
		break;
	default:	/* opnd_bytes must be modified manually */
		goto err_out;
	}

	return 1;

err_out:
	return 0;
}

static int __get_immv(struct insn *insn)
{
	switch (insn->opnd_bytes) {
	case 2:
		insn_field_set(&insn->immediate1, get_next(short, insn), 2);
		break;
	case 4:
		insn_field_set(&insn->immediate1, get_next(int, insn), 4);
		insn->immediate1.nbytes = 4;
		break;
	case 8:
		insn_field_set(&insn->immediate1, get_next(int, insn), 4);
		insn_field_set(&insn->immediate2, get_next(int, insn), 4);
		break;
	default:	/* opnd_bytes must be modified manually */
		goto err_out;
	}
	insn->immediate1.got = insn->immediate2.got = 1;

	return 1;
err_out:
	return 0;
}

static int __get_immptr(struct insn *insn)
{
	switch (insn->opnd_bytes) {
	case 2:
		insn_field_set(&insn->immediate1, get_next(short, insn), 2);
		break;
	case 4:
		insn_field_set(&insn->immediate1, get_next(int, insn), 4);
		break;
	case 8:
		/* ptr16:64 is not exist (no segment) */
		return 0;
	default:	/* opnd_bytes must be modified manually */
		goto err_out;
	}
	insn_field_set(&insn->immediate2, get_next(unsigned short, insn), 2);
	insn->immediate1.got = insn->immediate2.got = 1;

	return 1;
err_out:
	return 0;
}

int insn_get_immediate(struct insn *insn)
{
	int ret;

	if (insn->immediate.got)
		return 0;

	if (!insn->displacement.got) {
		ret = insn_get_displacement(insn);
		if (ret)
			return ret;
	}

	if (inat_has_moffset(insn->attr)) {
		if (!__get_moffset(insn))
			goto err_out;
		goto done;
	}

	if (!inat_has_immediate(insn->attr))
		/* no immediates */
		goto done;

	switch (inat_immediate_size(insn->attr)) {
	case INAT_IMM_BYTE:
		insn_field_set(&insn->immediate, get_next(signed char, insn), 1);
		break;
	case INAT_IMM_WORD:
		insn_field_set(&insn->immediate, get_next(short, insn), 2);
		break;
	case INAT_IMM_DWORD:
		insn_field_set(&insn->immediate, get_next(int, insn), 4);
		break;
	case INAT_IMM_QWORD:
		insn_field_set(&insn->immediate1, get_next(int, insn), 4);
		insn_field_set(&insn->immediate2, get_next(int, insn), 4);
		break;
	case INAT_IMM_PTR:
		if (!__get_immptr(insn))
			goto err_out;
		break;
	case INAT_IMM_VWORD32:
		if (!__get_immv32(insn))
			goto err_out;
		break;
	case INAT_IMM_VWORD:
		if (!__get_immv(insn))
			goto err_out;
		break;
	default:
		/* Here, insn must have an immediate, but failed */
		goto err_out;
	}
	if (inat_has_second_immediate(insn->attr)) {
		insn_field_set(&insn->immediate2, get_next(signed char, insn), 1);
	}
done:
	insn->immediate.got = 1;
	return 0;

err_out:
	return -ENODATA;
}

*/
int insn_get_length(struct insn *insn)
{
	int ret;

	if (insn->length)
		return 0;

	if (!insn->immediate.got) {
		ret = insn_get_immediate(insn);
		if (ret)
			return ret;
	}

	insn->length = (unsigned char)((unsigned long)insn->next_byte
				     - (unsigned long)insn->kaddr);

	return 0;
}

static inline int insn_complete(struct insn *insn)
{
	return insn->opcode.got && insn->modrm.got && insn->sib.got &&
		insn->displacement.got && insn->immediate.got;
}

int insn_decode(struct insn *insn, const void *kaddr, int buf_len, enum insn_mode m)
{
	int ret;


	if (m == INSN_MODE_KERN)
		insn_init(insn, kaddr, buf_len, IS_ENABLED(CONFIG_X86_64));
	else
		insn_init(insn, kaddr, buf_len, m == INSN_MODE_64);

	ret = insn_get_length(insn);
	if (ret)
		return ret;

	if (insn_complete(insn))
		return 0;

	return -EINVAL;
}
