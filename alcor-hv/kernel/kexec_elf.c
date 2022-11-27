
#define pr_fmt(fmt)	"kexec_elf: " fmt

#include <linux/elf.h>
#include <linux/kexec.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/types.h>

static inline bool elf_is_elf_file(const struct elfhdr *ehdr)
{
	return memcmp(ehdr->e_ident, ELFMAG, SELFMAG) == 0;
}

static uint64_t elf64_to_cpu(const struct elfhdr *ehdr, uint64_t value)
{
	if (ehdr->e_ident[EI_DATA] == ELFDATA2LSB)
		value = le64_to_cpu(value);
	else if (ehdr->e_ident[EI_DATA] == ELFDATA2MSB)
		value = be64_to_cpu(value);

	return value;
}

static uint32_t elf32_to_cpu(const struct elfhdr *ehdr, uint32_t value)
{
	if (ehdr->e_ident[EI_DATA] == ELFDATA2LSB)
		value = le32_to_cpu(value);
	else if (ehdr->e_ident[EI_DATA] == ELFDATA2MSB)
		value = be32_to_cpu(value);

	return value;
}

static uint16_t elf16_to_cpu(const struct elfhdr *ehdr, uint16_t value)
{
	if (ehdr->e_ident[EI_DATA] == ELFDATA2LSB)
		value = le16_to_cpu(value);
	else if (ehdr->e_ident[EI_DATA] == ELFDATA2MSB)
		value = be16_to_cpu(value);

	return value;
}

static bool elf_is_ehdr_sane(const struct elfhdr *ehdr, size_t buf_len)
{
	if (ehdr->e_phnum > 0 && ehdr->e_phentsize != sizeof(struct elf_phdr)) {
		pr_debug("Bad program header size.\n");
		return false;
	} else if (ehdr->e_shnum > 0 &&
		   ehdr->e_shentsize != sizeof(struct elf_shdr)) {
		pr_debug("Bad section header size.\n");
		return false;
	} else if (ehdr->e_ident[EI_VERSION] != EV_CURRENT ||
		   ehdr->e_version != EV_CURRENT) {
		pr_debug("Unknown ELF version.\n");
		return false;
	}

	if (ehdr->e_phoff > 0 && ehdr->e_phnum > 0) {
		size_t phdr_size;

		/*
		phdr_size = sizeof(struct elf_phdr) * ehdr->e_phnum;

		/* Sanity check the program header table location. */
		if (ehdr->e_phoff + phdr_size < ehdr->e_phoff) {
			pr_debug("Program headers at invalid location.\n");
			return false;
		} else if (ehdr->e_phoff + phdr_size > buf_len) {
			pr_debug("Program headers truncated.\n");
			return false;
		}
	}

	if (ehdr->e_shoff > 0 && ehdr->e_shnum > 0) {
		size_t shdr_size;

		/*
		shdr_size = sizeof(struct elf_shdr) * ehdr->e_shnum;

		/* Sanity check the section header table location. */
		if (ehdr->e_shoff + shdr_size < ehdr->e_shoff) {
			pr_debug("Section headers at invalid location.\n");
			return false;
		} else if (ehdr->e_shoff + shdr_size > buf_len) {
			pr_debug("Section headers truncated.\n");
			return false;
		}
	}

	return true;
}

static int elf_read_ehdr(const char *buf, size_t len, struct elfhdr *ehdr)
{
	struct elfhdr *buf_ehdr;

	if (len < sizeof(*buf_ehdr)) {
		pr_debug("Buffer is too small to hold ELF header.\n");
		return -ENOEXEC;
	}

	memset(ehdr, 0, sizeof(*ehdr));
	memcpy(ehdr->e_ident, buf, sizeof(ehdr->e_ident));
	if (!elf_is_elf_file(ehdr)) {
		pr_debug("No ELF header magic.\n");
		return -ENOEXEC;
	}

	if (ehdr->e_ident[EI_CLASS] != ELF_CLASS) {
		pr_debug("Not a supported ELF class.\n");
		return -ENOEXEC;
	} else  if (ehdr->e_ident[EI_DATA] != ELFDATA2LSB &&
		ehdr->e_ident[EI_DATA] != ELFDATA2MSB) {
		pr_debug("Not a supported ELF data format.\n");
		return -ENOEXEC;
	}

	buf_ehdr = (struct elfhdr *) buf;
	if (elf16_to_cpu(ehdr, buf_ehdr->e_ehsize) != sizeof(*buf_ehdr)) {
		pr_debug("Bad ELF header size.\n");
		return -ENOEXEC;
	}

	ehdr->e_type      = elf16_to_cpu(ehdr, buf_ehdr->e_type);
	ehdr->e_machine   = elf16_to_cpu(ehdr, buf_ehdr->e_machine);
	ehdr->e_version   = elf32_to_cpu(ehdr, buf_ehdr->e_version);
	ehdr->e_flags     = elf32_to_cpu(ehdr, buf_ehdr->e_flags);
	ehdr->e_phentsize = elf16_to_cpu(ehdr, buf_ehdr->e_phentsize);
	ehdr->e_phnum     = elf16_to_cpu(ehdr, buf_ehdr->e_phnum);
	ehdr->e_shentsize = elf16_to_cpu(ehdr, buf_ehdr->e_shentsize);
	ehdr->e_shnum     = elf16_to_cpu(ehdr, buf_ehdr->e_shnum);
	ehdr->e_shstrndx  = elf16_to_cpu(ehdr, buf_ehdr->e_shstrndx);

	switch (ehdr->e_ident[EI_CLASS]) {
	case ELFCLASS64:
		ehdr->e_entry = elf64_to_cpu(ehdr, buf_ehdr->e_entry);
		ehdr->e_phoff = elf64_to_cpu(ehdr, buf_ehdr->e_phoff);
		ehdr->e_shoff = elf64_to_cpu(ehdr, buf_ehdr->e_shoff);
		break;

	case ELFCLASS32:
		ehdr->e_entry = elf32_to_cpu(ehdr, buf_ehdr->e_entry);
		ehdr->e_phoff = elf32_to_cpu(ehdr, buf_ehdr->e_phoff);
		ehdr->e_shoff = elf32_to_cpu(ehdr, buf_ehdr->e_shoff);
		break;

	default:
		pr_debug("Unknown ELF class.\n");
		return -EINVAL;
	}

	return elf_is_ehdr_sane(ehdr, len) ? 0 : -ENOEXEC;
}

static bool elf_is_phdr_sane(const struct elf_phdr *phdr, size_t buf_len)
{

	if (phdr->p_offset + phdr->p_filesz < phdr->p_offset) {
		pr_debug("ELF segment location wraps around.\n");
		return false;
	} else if (phdr->p_offset + phdr->p_filesz > buf_len) {
		pr_debug("ELF segment not in file.\n");
		return false;
	} else if (phdr->p_paddr + phdr->p_memsz < phdr->p_paddr) {
		pr_debug("ELF segment address wraps around.\n");
		return false;
	}

	return true;
}

static int elf_read_phdr(const char *buf, size_t len,
			 struct kexec_elf_info *elf_info,
			 int idx)
{
	/* Override the const in proghdrs, we are the ones doing the loading. */
	struct elf_phdr *phdr = (struct elf_phdr *) &elf_info->proghdrs[idx];
	const struct elfhdr *ehdr = elf_info->ehdr;
	const char *pbuf;
	struct elf_phdr *buf_phdr;

	pbuf = buf + elf_info->ehdr->e_phoff + (idx * sizeof(*buf_phdr));
	buf_phdr = (struct elf_phdr *) pbuf;

	phdr->p_type   = elf32_to_cpu(elf_info->ehdr, buf_phdr->p_type);
	phdr->p_flags  = elf32_to_cpu(elf_info->ehdr, buf_phdr->p_flags);

	switch (ehdr->e_ident[EI_CLASS]) {
	case ELFCLASS64:
		phdr->p_offset = elf64_to_cpu(ehdr, buf_phdr->p_offset);
		phdr->p_paddr  = elf64_to_cpu(ehdr, buf_phdr->p_paddr);
		phdr->p_vaddr  = elf64_to_cpu(ehdr, buf_phdr->p_vaddr);
		phdr->p_filesz = elf64_to_cpu(ehdr, buf_phdr->p_filesz);
		phdr->p_memsz  = elf64_to_cpu(ehdr, buf_phdr->p_memsz);
		phdr->p_align  = elf64_to_cpu(ehdr, buf_phdr->p_align);
		break;

	case ELFCLASS32:
		phdr->p_offset = elf32_to_cpu(ehdr, buf_phdr->p_offset);
		phdr->p_paddr  = elf32_to_cpu(ehdr, buf_phdr->p_paddr);
		phdr->p_vaddr  = elf32_to_cpu(ehdr, buf_phdr->p_vaddr);
		phdr->p_filesz = elf32_to_cpu(ehdr, buf_phdr->p_filesz);
		phdr->p_memsz  = elf32_to_cpu(ehdr, buf_phdr->p_memsz);
		phdr->p_align  = elf32_to_cpu(ehdr, buf_phdr->p_align);
		break;

	default:
		pr_debug("Unknown ELF class.\n");
		return -EINVAL;
	}

	return elf_is_phdr_sane(phdr, len) ? 0 : -ENOEXEC;
}

static int elf_read_phdrs(const char *buf, size_t len,
			  struct kexec_elf_info *elf_info)
{
	size_t phdr_size, i;
	const struct elfhdr *ehdr = elf_info->ehdr;

	/*
	phdr_size = sizeof(struct elf_phdr) * ehdr->e_phnum;

	elf_info->proghdrs = kzalloc(phdr_size, GFP_KERNEL);
	if (!elf_info->proghdrs)
		return -ENOMEM;

	for (i = 0; i < ehdr->e_phnum; i++) {
		int ret;

		ret = elf_read_phdr(buf, len, elf_info, i);
		if (ret) {
			kfree(elf_info->proghdrs);
			elf_info->proghdrs = NULL;
			return ret;
		}
	}

	return 0;
}

static int elf_read_from_buffer(const char *buf, size_t len,
				struct elfhdr *ehdr,
				struct kexec_elf_info *elf_info)
{
	int ret;

	ret = elf_read_ehdr(buf, len, ehdr);
	if (ret)
		return ret;

	elf_info->buffer = buf;
	elf_info->ehdr = ehdr;
	if (ehdr->e_phoff > 0 && ehdr->e_phnum > 0) {
		ret = elf_read_phdrs(buf, len, elf_info);
		if (ret)
			return ret;
	}
	return 0;
}

void kexec_free_elf_info(struct kexec_elf_info *elf_info)
{
	kfree(elf_info->proghdrs);
	memset(elf_info, 0, sizeof(*elf_info));
}
int kexec_build_elf_info(const char *buf, size_t len, struct elfhdr *ehdr,
			       struct kexec_elf_info *elf_info)
{
	int i;
	int ret;

	ret = elf_read_from_buffer(buf, len, ehdr, elf_info);
	if (ret)
		return ret;

	/* Big endian vmlinux has type ET_DYN. */
	if (ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN) {
		pr_err("Not an ELF executable.\n");
		goto error;
	} else if (!elf_info->proghdrs) {
		pr_err("No ELF program header.\n");
		goto error;
	}

	for (i = 0; i < ehdr->e_phnum; i++) {
		/*
		if (elf_info->proghdrs[i].p_type == PT_INTERP) {
			pr_err("Requires an ELF interpreter.\n");
			goto error;
		}
	}

	return 0;
error:
	kexec_free_elf_info(elf_info);
	return -ENOEXEC;
}


int kexec_elf_probe(const char *buf, unsigned long len)
{
	struct elfhdr ehdr;
	struct kexec_elf_info elf_info;
	int ret;

	ret = kexec_build_elf_info(buf, len, &ehdr, &elf_info);
	if (ret)
		return ret;

	kexec_free_elf_info(&elf_info);

	return elf_check_arch(&ehdr) ? 0 : -ENOEXEC;
}

int kexec_elf_load(struct kimage *image, struct elfhdr *ehdr,
			 struct kexec_elf_info *elf_info,
			 struct kexec_buf *kbuf,
			 unsigned long *lowest_load_addr)
{
	unsigned long lowest_addr = UINT_MAX;
	int ret;
	size_t i;

	/* Read in the PT_LOAD segments. */
	for (i = 0; i < ehdr->e_phnum; i++) {
		unsigned long load_addr;
		size_t size;
		const struct elf_phdr *phdr;

		phdr = &elf_info->proghdrs[i];
		if (phdr->p_type != PT_LOAD)
			continue;

		size = phdr->p_filesz;
		if (size > phdr->p_memsz)
			size = phdr->p_memsz;

		kbuf->buffer = (void *) elf_info->buffer + phdr->p_offset;
		kbuf->bufsz = size;
		kbuf->memsz = phdr->p_memsz;
		kbuf->buf_align = phdr->p_align;
		kbuf->buf_min = phdr->p_paddr;
		kbuf->mem = KEXEC_BUF_MEM_UNKNOWN;
		ret = kexec_add_buffer(kbuf);
		if (ret)
			goto out;
		load_addr = kbuf->mem;

		if (load_addr < lowest_addr)
			lowest_addr = load_addr;
	}

	ret = 0;
 out:
	return ret;
}
