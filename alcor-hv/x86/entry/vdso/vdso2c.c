
#include <inttypes.h>
#include <stdint.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <err.h>

#include <sys/mman.h>
#include <sys/types.h>

#include <tools/le_byteshift.h>

#include <linux/elf.h>
#include <linux/types.h>
#include <linux/kernel.h>

const char *outfilename;

enum {
	sym_vvar_start,
	sym_vvar_page,
	sym_pvclock_page,
	sym_hvclock_page,
	sym_timens_page,
};

const int special_pages[] = {
	sym_vvar_page,
	sym_pvclock_page,
	sym_hvclock_page,
	sym_timens_page,
};

struct vdso_sym {
	const char *name;
	bool export;
};

struct vdso_sym required_syms[] = {
	[sym_vvar_start] = {"vvar_start", true},
	[sym_vvar_page] = {"vvar_page", true},
	[sym_pvclock_page] = {"pvclock_page", true},
	[sym_hvclock_page] = {"hvclock_page", true},
	[sym_timens_page] = {"timens_page", true},
	{"VDSO32_NOTE_MASK", true},
	{"__kernel_vsyscall", true},
	{"__kernel_sigreturn", true},
	{"__kernel_rt_sigreturn", true},
	{"int80_landing_pad", true},
	{"vdso32_rt_sigreturn_landing_pad", true},
	{"vdso32_sigreturn_landing_pad", true},
};

__attribute__((format(printf, 1, 2))) __attribute__((noreturn))
static void fail(const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	fprintf(stderr, "Error: ");
	vfprintf(stderr, format, ap);
	if (outfilename)
		unlink(outfilename);
	exit(1);
	va_end(ap);
}

#define GLE(x, bits, ifnot)						\
	__builtin_choose_expr(						\
		(sizeof(*(x)) == bits/8),				\
		(__typeof__(*(x)))get_unaligned_le##bits(x), ifnot)

extern void bad_get_le(void);
#define LAST_GLE(x)							\
	__builtin_choose_expr(sizeof(*(x)) == 1, *(x), bad_get_le())

#define GET_LE(x)							\
	GLE(x, 64, GLE(x, 32, GLE(x, 16, LAST_GLE(x))))

#define PLE(x, val, bits, ifnot)					\
	__builtin_choose_expr(						\
		(sizeof(*(x)) == bits/8),				\
		put_unaligned_le##bits((val), (x)), ifnot)

extern void bad_put_le(void);
#define LAST_PLE(x, val)						\
	__builtin_choose_expr(sizeof(*(x)) == 1, *(x) = (val), bad_put_le())

#define PUT_LE(x, val)					\
	PLE(x, val, 64, PLE(x, val, 32, PLE(x, val, 16, LAST_PLE(x, val))))


#define NSYMS ARRAY_SIZE(required_syms)

#define BITSFUNC3(name, bits, suffix) name##bits##suffix
#define BITSFUNC2(name, bits, suffix) BITSFUNC3(name, bits, suffix)
#define BITSFUNC(name) BITSFUNC2(name, ELF_BITS, )

#define INT_BITS BITSFUNC2(int, ELF_BITS, _t)

#define ELF_BITS_XFORM2(bits, x) Elf##bits##_##x
#define ELF_BITS_XFORM(bits, x) ELF_BITS_XFORM2(bits, x)
#define ELF(x) ELF_BITS_XFORM(ELF_BITS, x)

#define ELF_BITS 64
#include "vdso2c.h"
#undef ELF_BITS

#define ELF_BITS 32
#include "vdso2c.h"
#undef ELF_BITS

static void go(void *raw_addr, size_t raw_len,
	       void *stripped_addr, size_t stripped_len,
	       FILE *outfile, const char *name)
{
	Elf64_Ehdr *hdr = (Elf64_Ehdr *)raw_addr;

	if (hdr->e_ident[EI_CLASS] == ELFCLASS64) {
		go64(raw_addr, raw_len, stripped_addr, stripped_len,
		     outfile, name);
	} else if (hdr->e_ident[EI_CLASS] == ELFCLASS32) {
		go32(raw_addr, raw_len, stripped_addr, stripped_len,
		     outfile, name);
	} else {
		fail("unknown ELF class\n");
	}
}

static void map_input(const char *name, void **addr, size_t *len, int prot)
{
	off_t tmp_len;

	int fd = open(name, O_RDONLY);
	if (fd == -1)
		err(1, "open(%s)", name);

	tmp_len = lseek(fd, 0, SEEK_END);
	if (tmp_len == (off_t)-1)
		err(1, "lseek");

	if (*addr == MAP_FAILED)
		err(1, "mmap");

	close(fd);
}

int main(int argc, char **argv)
{
	size_t raw_len, stripped_len;
	void *raw_addr, *stripped_addr;
	FILE *outfile;
	char *name, *tmp;
	int namelen;

	if (argc != 4) {
		printf("Usage: vdso2c RAW_INPUT STRIPPED_INPUT OUTPUT\n");
		return 1;
	}

	/*
	name = strdup(argv[3]);
	namelen = strlen(name);
	if (namelen >= 3 && !strcmp(name + namelen - 3, ".so")) {
		name = NULL;
	} else {
		tmp = strrchr(name, '/');
		if (tmp)
			name = tmp + 1;
		tmp = strchr(name, '.');
		if (tmp)
			*tmp = '\0';
		for (tmp = name; *tmp; tmp++)
			if (*tmp == '-')
				*tmp = '_';
	}

	map_input(argv[1], &raw_addr, &raw_len, PROT_READ);
	map_input(argv[2], &stripped_addr, &stripped_len, PROT_READ);

	outfilename = argv[3];
	outfile = fopen(outfilename, "w");
	if (!outfile)
		err(1, "fopen(%s)", outfilename);

	go(raw_addr, raw_len, stripped_addr, stripped_len, outfile, name);

	munmap(raw_addr, raw_len);
	munmap(stripped_addr, stripped_len);
	fclose(outfile);

	return 0;
}
