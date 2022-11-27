#ifndef __ITERATORS_BPF_SKEL_H__
#define __ITERATORS_BPF_SKEL_H__

#include <bpf/skel_internal.h>

struct iterators_bpf {
	struct bpf_loader_ctx ctx;
	struct {
		struct bpf_map_desc rodata;
	} maps;
	struct {
		struct bpf_prog_desc dump_bpf_map;
		struct bpf_prog_desc dump_bpf_prog;
	} progs;
	struct {
		int dump_bpf_map_fd;
		int dump_bpf_prog_fd;
	} links;
	struct iterators_bpf__rodata {
	} *rodata;
};

static inline int
iterators_bpf__dump_bpf_map__attach(struct iterators_bpf *skel)
{
	int prog_fd = skel->progs.dump_bpf_map.prog_fd;
	int fd = skel_link_create(prog_fd, 0, BPF_TRACE_ITER);

	if (fd > 0)
		skel->links.dump_bpf_map_fd = fd;
	return fd;
}

static inline int
iterators_bpf__dump_bpf_prog__attach(struct iterators_bpf *skel)
{
	int prog_fd = skel->progs.dump_bpf_prog.prog_fd;
	int fd = skel_link_create(prog_fd, 0, BPF_TRACE_ITER);

	if (fd > 0)
		skel->links.dump_bpf_prog_fd = fd;
	return fd;
}

static inline int
iterators_bpf__attach(struct iterators_bpf *skel)
{
	int ret = 0;

	ret = ret < 0 ? ret : iterators_bpf__dump_bpf_map__attach(skel);
	ret = ret < 0 ? ret : iterators_bpf__dump_bpf_prog__attach(skel);
	return ret < 0 ? ret : 0;
}

static inline void
iterators_bpf__detach(struct iterators_bpf *skel)
{
	skel_closenz(skel->links.dump_bpf_map_fd);
	skel_closenz(skel->links.dump_bpf_prog_fd);
}
static void
iterators_bpf__destroy(struct iterators_bpf *skel)
{
	if (!skel)
		return;
	iterators_bpf__detach(skel);
	skel_closenz(skel->progs.dump_bpf_map.prog_fd);
	skel_closenz(skel->progs.dump_bpf_prog.prog_fd);
	skel_free_map_data(skel->rodata, skel->maps.rodata.initial_value, 4096);
	skel_closenz(skel->maps.rodata.map_fd);
	skel_free(skel);
}
static inline struct iterators_bpf *
iterators_bpf__open(void)
{
	struct iterators_bpf *skel;

	skel = skel_alloc(sizeof(*skel));
	if (!skel)
		goto cleanup;
	skel->ctx.sz = (void *)&skel->links - (void *)skel;
	skel->rodata = skel_prep_map_data((void *)"\
\x20\x20\x69\x64\x20\x6e\x61\x6d\x65\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
\x20\x20\x20\x6d\x61\x78\x5f\x65\x6e\x74\x72\x69\x65\x73\x0a\0\x25\x34\x75\x20\
\x25\x2d\x31\x36\x73\x25\x36\x64\x0a\0\x20\x20\x69\x64\x20\x6e\x61\x6d\x65\x20\
\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x61\x74\x74\x61\x63\x68\x65\
\x64\x0a\0\x25\x34\x75\x20\x25\x2d\x31\x36\x73\x20\x25\x73\x20\x25\x73\x0a\0", 4096, 98);
	if (!skel->rodata)
		goto cleanup;
	skel->maps.rodata.initial_value = (__u64) (long) skel->rodata;
	return skel;
cleanup:
	iterators_bpf__destroy(skel);
	return NULL;
}

static inline int
iterators_bpf__load(struct iterators_bpf *skel)
{
	struct bpf_load_and_run_opts opts = {};
	int err;

	opts.ctx = (struct bpf_loader_ctx *)skel;
	opts.data_sz = 6056;
	opts.data = (void *)"\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x9f\xeb\x01\0\
\x18\0\0\0\0\0\0\0\x1c\x04\0\0\x1c\x04\0\0\xf9\x04\0\0\0\0\0\0\0\0\0\x02\x02\0\
\0\0\x01\0\0\0\x02\0\0\x04\x10\0\0\0\x13\0\0\0\x03\0\0\0\0\0\0\0\x18\0\0\0\x04\
\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\x02\x08\0\0\0\0\0\0\0\0\0\0\x02\x0d\0\0\0\0\0\0\
\0\x01\0\0\x0d\x06\0\0\0\x1c\0\0\0\x01\0\0\0\x20\0\0\0\0\0\0\x01\x04\0\0\0\x20\
\0\0\x01\x24\0\0\0\x01\0\0\x0c\x05\0\0\0\xa3\0\0\0\x03\0\0\x04\x18\0\0\0\xb1\0\
\0\0\x09\0\0\0\0\0\0\0\xb5\0\0\0\x0b\0\0\0\x40\0\0\0\xc0\0\0\0\x0b\0\0\0\x80\0\
\0\0\0\0\0\0\0\0\0\x02\x0a\0\0\0\xc8\0\0\0\0\0\0\x07\0\0\0\0\xd1\0\0\0\0\0\0\
\x08\x0c\0\0\0\xd7\0\0\0\0\0\0\x01\x08\0\0\0\x40\0\0\0\x94\x01\0\0\x03\0\0\x04\
\x18\0\0\0\x9c\x01\0\0\x0e\0\0\0\0\0\0\0\x9f\x01\0\0\x11\0\0\0\x20\0\0\0\xa4\
\x01\0\0\x0e\0\0\0\xa0\0\0\0\xb0\x01\0\0\0\0\0\x08\x0f\0\0\0\xb6\x01\0\0\0\0\0\
\x01\x04\0\0\0\x20\0\0\0\xc3\x01\0\0\0\0\0\x01\x01\0\0\0\x08\0\0\x01\0\0\0\0\0\
\0\0\x03\0\0\0\0\x10\0\0\0\x12\0\0\0\x10\0\0\0\xc8\x01\0\0\0\0\0\x01\x04\0\0\0\
\x20\0\0\0\0\0\0\0\0\0\0\x02\x14\0\0\0\x2c\x02\0\0\x02\0\0\x04\x10\0\0\0\x13\0\
\0\0\x03\0\0\0\0\0\0\0\x3f\x02\0\0\x15\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\x02\x18\0\
\0\0\0\0\0\0\x01\0\0\x0d\x06\0\0\0\x1c\0\0\0\x13\0\0\0\x44\x02\0\0\x01\0\0\x0c\
\x16\0\0\0\x90\x02\0\0\x01\0\0\x04\x08\0\0\0\x99\x02\0\0\x19\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\x02\x1a\0\0\0\xea\x02\0\0\x06\0\0\x04\x38\0\0\0\x9c\x01\0\0\x0e\0\0\
\0\0\0\0\0\x9f\x01\0\0\x11\0\0\0\x20\0\0\0\xf7\x02\0\0\x1b\0\0\0\xc0\0\0\0\x08\
\x03\0\0\x15\0\0\0\0\x01\0\0\x11\x03\0\0\x1d\0\0\0\x40\x01\0\0\x1b\x03\0\0\x1e\
\0\0\0\x80\x01\0\0\0\0\0\0\0\0\0\x02\x1c\0\0\0\0\0\0\0\0\0\0\x0a\x10\0\0\0\0\0\
\0\0\0\0\0\x02\x1f\0\0\0\0\0\0\0\0\0\0\x02\x20\0\0\0\x65\x03\0\0\x02\0\0\x04\
\x08\0\0\0\x73\x03\0\0\x0e\0\0\0\0\0\0\0\x7c\x03\0\0\x0e\0\0\0\x20\0\0\0\x1b\
\x03\0\0\x03\0\0\x04\x18\0\0\0\x86\x03\0\0\x1b\0\0\0\0\0\0\0\x8e\x03\0\0\x21\0\
\0\0\x40\0\0\0\x94\x03\0\0\x23\0\0\0\x80\0\0\0\0\0\0\0\0\0\0\x02\x22\0\0\0\0\0\
\0\0\0\0\0\x02\x24\0\0\0\x98\x03\0\0\x01\0\0\x04\x04\0\0\0\xa3\x03\0\0\x0e\0\0\
\0\0\0\0\0\x0c\x04\0\0\x01\0\0\x04\x04\0\0\0\x15\x04\0\0\x0e\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\x03\0\0\0\0\x1c\0\0\0\x12\0\0\0\x23\0\0\0\x8b\x04\0\0\0\0\0\x0e\x25\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\0\x1c\0\0\0\x12\0\0\0\x0e\0\0\0\x9f\x04\
\0\0\0\0\0\x0e\x27\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\0\x1c\0\0\0\x12\0\0\0\
\x20\0\0\0\xb5\x04\0\0\0\0\0\x0e\x29\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\0\
\x1c\0\0\0\x12\0\0\0\x11\0\0\0\xca\x04\0\0\0\0\0\x0e\x2b\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\x03\0\0\0\0\x10\0\0\0\x12\0\0\0\x04\0\0\0\xe1\x04\0\0\0\0\0\x0e\x2d\0\0\
\0\x01\0\0\0\xe9\x04\0\0\x04\0\0\x0f\x62\0\0\0\x26\0\0\0\0\0\0\0\x23\0\0\0\x28\
\0\0\0\x23\0\0\0\x0e\0\0\0\x2a\0\0\0\x31\0\0\0\x20\0\0\0\x2c\0\0\0\x51\0\0\0\
\x11\0\0\0\xf1\x04\0\0\x01\0\0\x0f\x04\0\0\0\x2e\0\0\0\0\0\0\0\x04\0\0\0\0\x62\
\x70\x66\x5f\x69\x74\x65\x72\x5f\x5f\x62\x70\x66\x5f\x6d\x61\x70\0\x6d\x65\x74\
\x61\0\x6d\x61\x70\0\x63\x74\x78\0\x69\x6e\x74\0\x64\x75\x6d\x70\x5f\x62\x70\
\x66\x5f\x6d\x61\x70\0\x69\x74\x65\x72\x2f\x62\x70\x66\x5f\x6d\x61\x70\0\x30\
\x3a\x30\0\x2f\x77\x2f\x6e\x65\x74\x2d\x6e\x65\x78\x74\x2f\x6b\x65\x72\x6e\x65\
\x6c\x2f\x62\x70\x66\x2f\x70\x72\x65\x6c\x6f\x61\x64\x2f\x69\x74\x65\x72\x61\
\x74\x6f\x72\x73\x2f\x69\x74\x65\x72\x61\x74\x6f\x72\x73\x2e\x62\x70\x66\x2e\
\x63\0\x09\x73\x74\x72\x75\x63\x74\x20\x73\x65\x71\x5f\x66\x69\x6c\x65\x20\x2a\
\x73\x65\x71\x20\x3d\x20\x63\x74\x78\x2d\x3e\x6d\x65\x74\x61\x2d\x3e\x73\x65\
\x71\x3b\0\x62\x70\x66\x5f\x69\x74\x65\x72\x5f\x6d\x65\x74\x61\0\x73\x65\x71\0\
\x73\x65\x73\x73\x69\x6f\x6e\x5f\x69\x64\0\x73\x65\x71\x5f\x6e\x75\x6d\0\x73\
\x65\x71\x5f\x66\x69\x6c\x65\0\x5f\x5f\x75\x36\x34\0\x75\x6e\x73\x69\x67\x6e\
\x65\x64\x20\x6c\x6f\x6e\x67\x20\x6c\x6f\x6e\x67\0\x30\x3a\x31\0\x09\x73\x74\
\x72\x75\x63\x74\x20\x62\x70\x66\x5f\x6d\x61\x70\x20\x2a\x6d\x61\x70\x20\x3d\
\x20\x63\x74\x78\x2d\x3e\x6d\x61\x70\x3b\0\x09\x69\x66\x20\x28\x21\x6d\x61\x70\
\x29\0\x09\x5f\x5f\x75\x36\x34\x20\x73\x65\x71\x5f\x6e\x75\x6d\x20\x3d\x20\x63\
\x74\x78\x2d\x3e\x6d\x65\x74\x61\x2d\x3e\x73\x65\x71\x5f\x6e\x75\x6d\x3b\0\x30\
\x3a\x32\0\x09\x69\x66\x20\x28\x73\x65\x71\x5f\x6e\x75\x6d\x20\x3d\x3d\x20\x30\
\x29\0\x09\x09\x42\x50\x46\x5f\x53\x45\x51\x5f\x50\x52\x49\x4e\x54\x46\x28\x73\
\x65\x71\x2c\x20\x22\x20\x20\x69\x64\x20\x6e\x61\x6d\x65\x20\x20\x20\x20\x20\
\x20\x20\x20\x20\x20\x20\x20\x20\x6d\x61\x78\x5f\x65\x6e\x74\x72\x69\x65\x73\
\x5c\x6e\x22\x29\x3b\0\x62\x70\x66\x5f\x6d\x61\x70\0\x69\x64\0\x6e\x61\x6d\x65\
\0\x6d\x61\x78\x5f\x65\x6e\x74\x72\x69\x65\x73\0\x5f\x5f\x75\x33\x32\0\x75\x6e\
\x73\x69\x67\x6e\x65\x64\x20\x69\x6e\x74\0\x63\x68\x61\x72\0\x5f\x5f\x41\x52\
\x52\x41\x59\x5f\x53\x49\x5a\x45\x5f\x54\x59\x50\x45\x5f\x5f\0\x09\x42\x50\x46\
\x5f\x53\x45\x51\x5f\x50\x52\x49\x4e\x54\x46\x28\x73\x65\x71\x2c\x20\x22\x25\
\x34\x75\x20\x25\x2d\x31\x36\x73\x25\x36\x64\x5c\x6e\x22\x2c\x20\x6d\x61\x70\
\x2d\x3e\x69\x64\x2c\x20\x6d\x61\x70\x2d\x3e\x6e\x61\x6d\x65\x2c\x20\x6d\x61\
\x70\x2d\x3e\x6d\x61\x78\x5f\x65\x6e\x74\x72\x69\x65\x73\x29\x3b\0\x7d\0\x62\
\x70\x66\x5f\x69\x74\x65\x72\x5f\x5f\x62\x70\x66\x5f\x70\x72\x6f\x67\0\x70\x72\
\x6f\x67\0\x64\x75\x6d\x70\x5f\x62\x70\x66\x5f\x70\x72\x6f\x67\0\x69\x74\x65\
\x72\x2f\x62\x70\x66\x5f\x70\x72\x6f\x67\0\x09\x73\x74\x72\x75\x63\x74\x20\x62\
\x70\x66\x5f\x70\x72\x6f\x67\x20\x2a\x70\x72\x6f\x67\x20\x3d\x20\x63\x74\x78\
\x2d\x3e\x70\x72\x6f\x67\x3b\0\x09\x69\x66\x20\x28\x21\x70\x72\x6f\x67\x29\0\
\x62\x70\x66\x5f\x70\x72\x6f\x67\0\x61\x75\x78\0\x09\x61\x75\x78\x20\x3d\x20\
\x70\x72\x6f\x67\x2d\x3e\x61\x75\x78\x3b\0\x09\x09\x42\x50\x46\x5f\x53\x45\x51\
\x5f\x50\x52\x49\x4e\x54\x46\x28\x73\x65\x71\x2c\x20\x22\x20\x20\x69\x64\x20\
\x6e\x61\x6d\x65\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x61\x74\
\x74\x61\x63\x68\x65\x64\x5c\x6e\x22\x29\x3b\0\x62\x70\x66\x5f\x70\x72\x6f\x67\
\x5f\x61\x75\x78\0\x61\x74\x74\x61\x63\x68\x5f\x66\x75\x6e\x63\x5f\x6e\x61\x6d\
\x65\0\x64\x73\x74\x5f\x70\x72\x6f\x67\0\x66\x75\x6e\x63\x5f\x69\x6e\x66\x6f\0\
\x62\x74\x66\0\x09\x42\x50\x46\x5f\x53\x45\x51\x5f\x50\x52\x49\x4e\x54\x46\x28\
\x73\x65\x71\x2c\x20\x22\x25\x34\x75\x20\x25\x2d\x31\x36\x73\x20\x25\x73\x20\
\x25\x73\x5c\x6e\x22\x2c\x20\x61\x75\x78\x2d\x3e\x69\x64\x2c\0\x30\x3a\x34\0\
\x30\x3a\x35\0\x09\x69\x66\x20\x28\x21\x62\x74\x66\x29\0\x62\x70\x66\x5f\x66\
\x75\x6e\x63\x5f\x69\x6e\x66\x6f\0\x69\x6e\x73\x6e\x5f\x6f\x66\x66\0\x74\x79\
\x70\x65\x5f\x69\x64\0\x30\0\x73\x74\x72\x69\x6e\x67\x73\0\x74\x79\x70\x65\x73\
\0\x68\x64\x72\0\x62\x74\x66\x5f\x68\x65\x61\x64\x65\x72\0\x73\x74\x72\x5f\x6c\
\x65\x6e\0\x09\x74\x79\x70\x65\x73\x20\x3d\x20\x62\x74\x66\x2d\x3e\x74\x79\x70\
\x65\x73\x3b\0\x09\x62\x70\x66\x5f\x70\x72\x6f\x62\x65\x5f\x72\x65\x61\x64\x5f\
\x6b\x65\x72\x6e\x65\x6c\x28\x26\x74\x2c\x20\x73\x69\x7a\x65\x6f\x66\x28\x74\
\x29\x2c\x20\x74\x79\x70\x65\x73\x20\x2b\x20\x62\x74\x66\x5f\x69\x64\x29\x3b\0\
\x09\x73\x74\x72\x20\x3d\x20\x62\x74\x66\x2d\x3e\x73\x74\x72\x69\x6e\x67\x73\
\x3b\0\x62\x74\x66\x5f\x74\x79\x70\x65\0\x6e\x61\x6d\x65\x5f\x6f\x66\x66\0\x09\
\x6e\x61\x6d\x65\x5f\x6f\x66\x66\x20\x3d\x20\x42\x50\x46\x5f\x43\x4f\x52\x45\
\x5f\x52\x45\x41\x44\x28\x74\x2c\x20\x6e\x61\x6d\x65\x5f\x6f\x66\x66\x29\x3b\0\
\x30\x3a\x32\x3a\x30\0\x09\x69\x66\x20\x28\x6e\x61\x6d\x65\x5f\x6f\x66\x66\x20\
\x3e\x3d\x20\x62\x74\x66\x2d\x3e\x68\x64\x72\x2e\x73\x74\x72\x5f\x6c\x65\x6e\
\x29\0\x09\x72\x65\x74\x75\x72\x6e\x20\x73\x74\x72\x20\x2b\x20\x6e\x61\x6d\x65\
\x5f\x6f\x66\x66\x3b\0\x30\x3a\x33\0\x64\x75\x6d\x70\x5f\x62\x70\x66\x5f\x6d\
\x61\x70\x2e\x5f\x5f\x5f\x66\x6d\x74\0\x64\x75\x6d\x70\x5f\x62\x70\x66\x5f\x6d\
\x61\x70\x2e\x5f\x5f\x5f\x66\x6d\x74\x2e\x31\0\x64\x75\x6d\x70\x5f\x62\x70\x66\
\x5f\x70\x72\x6f\x67\x2e\x5f\x5f\x5f\x66\x6d\x74\0\x64\x75\x6d\x70\x5f\x62\x70\
\x66\x5f\x70\x72\x6f\x67\x2e\x5f\x5f\x5f\x66\x6d\x74\x2e\x32\0\x4c\x49\x43\x45\
\x4e\x53\x45\0\x2e\x72\x6f\x64\x61\x74\x61\0\x6c\x69\x63\x65\x6e\x73\x65\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x2d\x09\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x02\0\0\
\0\x04\0\0\0\x62\0\0\0\x01\0\0\0\x80\x04\0\0\0\0\0\0\0\0\0\0\x69\x74\x65\x72\
\x61\x74\x6f\x72\x2e\x72\x6f\x64\x61\x74\x61\0\0\0\0\0\0\0\0\0\0\0\0\0\x2f\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\x20\x20\x69\x64\x20\x6e\x61\x6d\x65\x20\x20\x20\x20\
\x20\x20\x20\x20\x20\x20\x20\x20\x20\x6d\x61\x78\x5f\x65\x6e\x74\x72\x69\x65\
\x73\x0a\0\x25\x34\x75\x20\x25\x2d\x31\x36\x73\x25\x36\x64\x0a\0\x20\x20\x69\
\x64\x20\x6e\x61\x6d\x65\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
\x61\x74\x74\x61\x63\x68\x65\x64\x0a\0\x25\x34\x75\x20\x25\x2d\x31\x36\x73\x20\
\x25\x73\x20\x25\x73\x0a\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x47\x50\x4c\0\0\0\0\0\
\x79\x12\0\0\0\0\0\0\x79\x26\0\0\0\0\0\0\x79\x17\x08\0\0\0\0\0\x15\x07\x1b\0\0\
\0\0\0\x79\x11\0\0\0\0\0\0\x79\x11\x10\0\0\0\0\0\x55\x01\x08\0\0\0\0\0\xbf\xa4\
\0\0\0\0\0\0\x07\x04\0\0\xe8\xff\xff\xff\xbf\x61\0\0\0\0\0\0\x18\x62\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\xb7\x03\0\0\x23\0\0\0\xb7\x05\0\0\0\0\0\0\x85\0\0\0\x7e\0\0\
\0\x61\x71\0\0\0\0\0\0\x7b\x1a\xe8\xff\0\0\0\0\xb7\x01\0\0\x04\0\0\0\xbf\x72\0\
\0\0\0\0\0\x0f\x12\0\0\0\0\0\0\x7b\x2a\xf0\xff\0\0\0\0\x61\x71\x14\0\0\0\0\0\
\x7b\x1a\xf8\xff\0\0\0\0\xbf\xa4\0\0\0\0\0\0\x07\x04\0\0\xe8\xff\xff\xff\xbf\
\x61\0\0\0\0\0\0\x18\x62\0\0\0\0\0\0\0\0\0\0\x23\0\0\0\xb7\x03\0\0\x0e\0\0\0\
\xb7\x05\0\0\x18\0\0\0\x85\0\0\0\x7e\0\0\0\xb7\0\0\0\0\0\0\0\x95\0\0\0\0\0\0\0\
\0\0\0\0\x07\0\0\0\0\0\0\0\x42\0\0\0\x7b\0\0\0\x1e\x3c\x01\0\x01\0\0\0\x42\0\0\
\0\x7b\0\0\0\x24\x3c\x01\0\x02\0\0\0\x42\0\0\0\xee\0\0\0\x1d\x44\x01\0\x03\0\0\
\0\x42\0\0\0\x0f\x01\0\0\x06\x4c\x01\0\x04\0\0\0\x42\0\0\0\x1a\x01\0\0\x17\x40\
\x01\0\x05\0\0\0\x42\0\0\0\x1a\x01\0\0\x1d\x40\x01\0\x06\0\0\0\x42\0\0\0\x43\
\x01\0\0\x06\x58\x01\0\x08\0\0\0\x42\0\0\0\x56\x01\0\0\x03\x5c\x01\0\x0f\0\0\0\
\x42\0\0\0\xdc\x01\0\0\x02\x64\x01\0\x1f\0\0\0\x42\0\0\0\x2a\x02\0\0\x01\x6c\
\x01\0\0\0\0\0\x02\0\0\0\x3e\0\0\0\0\0\0\0\x08\0\0\0\x08\0\0\0\x3e\0\0\0\0\0\0\
\0\x10\0\0\0\x02\0\0\0\xea\0\0\0\0\0\0\0\x20\0\0\0\x02\0\0\0\x3e\0\0\0\0\0\0\0\
\x28\0\0\0\x08\0\0\0\x3f\x01\0\0\0\0\0\0\x78\0\0\0\x0d\0\0\0\x3e\0\0\0\0\0\0\0\
\x88\0\0\0\x0d\0\0\0\xea\0\0\0\0\0\0\0\xa8\0\0\0\x0d\0\0\0\x3f\x01\0\0\0\0\0\0\
\x1a\0\0\0\x21\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\x64\x75\x6d\x70\x5f\x62\x70\x66\x5f\x6d\x61\x70\0\0\0\0\
\0\0\0\0\x1c\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\x10\0\0\0\0\0\0\
\0\0\0\0\0\x0a\0\0\0\x01\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\x10\0\0\0\0\0\0\0\x62\x70\x66\x5f\x69\x74\x65\x72\x5f\x62\x70\x66\x5f\x6d\
\x61\x70\0\0\0\0\0\0\0\0\x47\x50\x4c\0\0\0\0\0\x79\x12\0\0\0\0\0\0\x79\x26\0\0\
\0\0\0\0\x79\x12\x08\0\0\0\0\0\x15\x02\x3c\0\0\0\0\0\x79\x11\0\0\0\0\0\0\x79\
\x27\0\0\0\0\0\0\x79\x11\x10\0\0\0\0\0\x55\x01\x08\0\0\0\0\0\xbf\xa4\0\0\0\0\0\
\0\x07\x04\0\0\xd0\xff\xff\xff\xbf\x61\0\0\0\0\0\0\x18\x62\0\0\0\0\0\0\0\0\0\0\
\x31\0\0\0\xb7\x03\0\0\x20\0\0\0\xb7\x05\0\0\0\0\0\0\x85\0\0\0\x7e\0\0\0\x7b\
\x6a\xc8\xff\0\0\0\0\x61\x71\0\0\0\0\0\0\x7b\x1a\xd0\xff\0\0\0\0\xb7\x03\0\0\
\x04\0\0\0\xbf\x79\0\0\0\0\0\0\x0f\x39\0\0\0\0\0\0\x79\x71\x28\0\0\0\0\0\x79\
\x78\x30\0\0\0\0\0\x15\x08\x18\0\0\0\0\0\xb7\x02\0\0\0\0\0\0\x0f\x21\0\0\0\0\0\
\0\x61\x11\x04\0\0\0\0\0\x79\x83\x08\0\0\0\0\0\x67\x01\0\0\x03\0\0\0\x0f\x13\0\
\0\0\0\0\0\x79\x86\0\0\0\0\0\0\xbf\xa1\0\0\0\0\0\0\x07\x01\0\0\xf8\xff\xff\xff\
\xb7\x02\0\0\x08\0\0\0\x85\0\0\0\x71\0\0\0\xb7\x01\0\0\0\0\0\0\x79\xa3\xf8\xff\
\0\0\0\0\x0f\x13\0\0\0\0\0\0\xbf\xa1\0\0\0\0\0\0\x07\x01\0\0\xf4\xff\xff\xff\
\xb7\x02\0\0\x04\0\0\0\x85\0\0\0\x71\0\0\0\xb7\x03\0\0\x04\0\0\0\x61\xa1\xf4\
\xff\0\0\0\0\x61\x82\x10\0\0\0\0\0\x3d\x21\x02\0\0\0\0\0\x0f\x16\0\0\0\0\0\0\
\xbf\x69\0\0\0\0\0\0\x7b\x9a\xd8\xff\0\0\0\0\x79\x71\x18\0\0\0\0\0\x7b\x1a\xe0\
\xff\0\0\0\0\x79\x71\x20\0\0\0\0\0\x79\x11\0\0\0\0\0\0\x0f\x31\0\0\0\0\0\0\x7b\
\x1a\xe8\xff\0\0\0\0\xbf\xa4\0\0\0\0\0\0\x07\x04\0\0\xd0\xff\xff\xff\x79\xa1\
\xc8\xff\0\0\0\0\x18\x62\0\0\0\0\0\0\0\0\0\0\x51\0\0\0\xb7\x03\0\0\x11\0\0\0\
\xb7\x05\0\0\x20\0\0\0\x85\0\0\0\x7e\0\0\0\xb7\0\0\0\0\0\0\0\x95\0\0\0\0\0\0\0\
\0\0\0\0\x17\0\0\0\0\0\0\0\x42\0\0\0\x7b\0\0\0\x1e\x80\x01\0\x01\0\0\0\x42\0\0\
\0\x7b\0\0\0\x24\x80\x01\0\x02\0\0\0\x42\0\0\0\x60\x02\0\0\x1f\x88\x01\0\x03\0\
\0\0\x42\0\0\0\x84\x02\0\0\x06\x94\x01\0\x04\0\0\0\x42\0\0\0\x1a\x01\0\0\x17\
\x84\x01\0\x05\0\0\0\x42\0\0\0\x9d\x02\0\0\x0e\xa0\x01\0\x06\0\0\0\x42\0\0\0\
\x1a\x01\0\0\x1d\x84\x01\0\x07\0\0\0\x42\0\0\0\x43\x01\0\0\x06\xa4\x01\0\x09\0\
\0\0\x42\0\0\0\xaf\x02\0\0\x03\xa8\x01\0\x11\0\0\0\x42\0\0\0\x1f\x03\0\0\x02\
\xb0\x01\0\x18\0\0\0\x42\0\0\0\x5a\x03\0\0\x06\x04\x01\0\x1b\0\0\0\x42\0\0\0\0\
\0\0\0\0\0\0\0\x1c\0\0\0\x42\0\0\0\xab\x03\0\0\x0f\x10\x01\0\x1d\0\0\0\x42\0\0\
\0\xc0\x03\0\0\x2d\x14\x01\0\x1f\0\0\0\x42\0\0\0\xf7\x03\0\0\x0d\x0c\x01\0\x21\
\0\0\0\x42\0\0\0\0\0\0\0\0\0\0\0\x22\0\0\0\x42\0\0\0\xc0\x03\0\0\x02\x14\x01\0\
\x25\0\0\0\x42\0\0\0\x1e\x04\0\0\x0d\x18\x01\0\x28\0\0\0\x42\0\0\0\0\0\0\0\0\0\
\0\0\x29\0\0\0\x42\0\0\0\x1e\x04\0\0\x0d\x18\x01\0\x2c\0\0\0\x42\0\0\0\x1e\x04\
\0\0\x0d\x18\x01\0\x2d\0\0\0\x42\0\0\0\x4c\x04\0\0\x1b\x1c\x01\0\x2e\0\0\0\x42\
\0\0\0\x4c\x04\0\0\x06\x1c\x01\0\x2f\0\0\0\x42\0\0\0\x6f\x04\0\0\x0d\x24\x01\0\
\x31\0\0\0\x42\0\0\0\x1f\x03\0\0\x02\xb0\x01\0\x40\0\0\0\x42\0\0\0\x2a\x02\0\0\
\x01\xc0\x01\0\0\0\0\0\x14\0\0\0\x3e\0\0\0\0\0\0\0\x08\0\0\0\x08\0\0\0\x3e\0\0\
\0\0\0\0\0\x10\0\0\0\x14\0\0\0\xea\0\0\0\0\0\0\0\x20\0\0\0\x14\0\0\0\x3e\0\0\0\
\0\0\0\0\x28\0\0\0\x18\0\0\0\x3e\0\0\0\0\0\0\0\x30\0\0\0\x08\0\0\0\x3f\x01\0\0\
\0\0\0\0\x88\0\0\0\x1a\0\0\0\x3e\0\0\0\0\0\0\0\x98\0\0\0\x1a\0\0\0\xea\0\0\0\0\
\0\0\0\xb0\0\0\0\x1a\0\0\0\x52\x03\0\0\0\0\0\0\xb8\0\0\0\x1a\0\0\0\x56\x03\0\0\
\0\0\0\0\xc8\0\0\0\x1f\0\0\0\x84\x03\0\0\0\0\0\0\xe0\0\0\0\x20\0\0\0\xea\0\0\0\
\0\0\0\0\xf8\0\0\0\x20\0\0\0\x3e\0\0\0\0\0\0\0\x20\x01\0\0\x24\0\0\0\x3e\0\0\0\
\0\0\0\0\x58\x01\0\0\x1a\0\0\0\xea\0\0\0\0\0\0\0\x68\x01\0\0\x20\0\0\0\x46\x04\
\0\0\0\0\0\0\x90\x01\0\0\x1a\0\0\0\x3f\x01\0\0\0\0\0\0\xa0\x01\0\0\x1a\0\0\0\
\x87\x04\0\0\0\0\0\0\xa8\x01\0\0\x18\0\0\0\x3e\0\0\0\0\0\0\0\x1a\0\0\0\x42\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\x64\x75\x6d\x70\x5f\x62\x70\x66\x5f\x70\x72\x6f\x67\0\0\0\0\0\0\0\x1c\0\0\
\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\x10\0\0\0\0\0\0\0\0\0\0\0\x1a\0\
\0\0\x01\0\0\0\0\0\0\0\x13\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x10\0\0\0\0\0\
\0\0\x62\x70\x66\x5f\x69\x74\x65\x72\x5f\x62\x70\x66\x5f\x70\x72\x6f\x67\0\0\0\
\0\0\0\0";
	opts.insns_sz = 2216;
	opts.insns = (void *)"\
\xbf\x16\0\0\0\0\0\0\xbf\xa1\0\0\0\0\0\0\x07\x01\0\0\x78\xff\xff\xff\xb7\x02\0\
\0\x88\0\0\0\xb7\x03\0\0\0\0\0\0\x85\0\0\0\x71\0\0\0\x05\0\x14\0\0\0\0\0\x61\
\xa1\x78\xff\0\0\0\0\xd5\x01\x01\0\0\0\0\0\x85\0\0\0\xa8\0\0\0\x61\xa1\x7c\xff\
\0\0\0\0\xd5\x01\x01\0\0\0\0\0\x85\0\0\0\xa8\0\0\0\x61\xa1\x80\xff\0\0\0\0\xd5\
\x01\x01\0\0\0\0\0\x85\0\0\0\xa8\0\0\0\x61\xa1\x84\xff\0\0\0\0\xd5\x01\x01\0\0\
\0\0\0\x85\0\0\0\xa8\0\0\0\x18\x60\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x61\x01\0\0\0\0\
\0\0\xd5\x01\x02\0\0\0\0\0\xbf\x19\0\0\0\0\0\0\x85\0\0\0\xa8\0\0\0\xbf\x70\0\0\
\0\0\0\0\x95\0\0\0\0\0\0\0\x61\x60\x08\0\0\0\0\0\x18\x61\0\0\0\0\0\0\0\0\0\0\
\x48\x0e\0\0\x63\x01\0\0\0\0\0\0\x61\x60\x0c\0\0\0\0\0\x18\x61\0\0\0\0\0\0\0\0\
\0\0\x44\x0e\0\0\x63\x01\0\0\0\0\0\0\x79\x60\x10\0\0\0\0\0\x18\x61\0\0\0\0\0\0\
\0\0\0\0\x38\x0e\0\0\x7b\x01\0\0\0\0\0\0\x18\x60\0\0\0\0\0\0\0\0\0\0\0\x05\0\0\
\x18\x61\0\0\0\0\0\0\0\0\0\0\x30\x0e\0\0\x7b\x01\0\0\0\0\0\0\xb7\x01\0\0\x12\0\
\0\0\x18\x62\0\0\0\0\0\0\0\0\0\0\x30\x0e\0\0\xb7\x03\0\0\x1c\0\0\0\x85\0\0\0\
\xa6\0\0\0\xbf\x07\0\0\0\0\0\0\xc5\x07\xd4\xff\0\0\0\0\x63\x7a\x78\xff\0\0\0\0\
\x61\xa0\x78\xff\0\0\0\0\x18\x61\0\0\0\0\0\0\0\0\0\0\x80\x0e\0\0\x63\x01\0\0\0\
\0\0\0\x61\x60\x1c\0\0\0\0\0\x15\0\x03\0\0\0\0\0\x18\x61\0\0\0\0\0\0\0\0\0\0\
\x5c\x0e\0\0\x63\x01\0\0\0\0\0\0\xb7\x01\0\0\0\0\0\0\x18\x62\0\0\0\0\0\0\0\0\0\
\0\x50\x0e\0\0\xb7\x03\0\0\x48\0\0\0\x85\0\0\0\xa6\0\0\0\xbf\x07\0\0\0\0\0\0\
\xc5\x07\xc3\xff\0\0\0\0\x18\x61\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x63\x71\0\0\0\0\0\
\0\x79\x63\x20\0\0\0\0\0\x15\x03\x08\0\0\0\0\0\x18\x61\0\0\0\0\0\0\0\0\0\0\x98\
\x0e\0\0\xb7\x02\0\0\x62\0\0\0\x61\x60\x04\0\0\0\0\0\x45\0\x02\0\x01\0\0\0\x85\
\0\0\0\x94\0\0\0\x05\0\x01\0\0\0\0\0\x85\0\0\0\x71\0\0\0\x18\x62\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\x61\x20\0\0\0\0\0\0\x18\x61\0\0\0\0\0\0\0\0\0\0\x08\x0f\0\0\x63\
\x01\0\0\0\0\0\0\x18\x60\0\0\0\0\0\0\0\0\0\0\0\x0f\0\0\x18\x61\0\0\0\0\0\0\0\0\
\0\0\x10\x0f\0\0\x7b\x01\0\0\0\0\0\0\x18\x60\0\0\0\0\0\0\0\0\0\0\x98\x0e\0\0\
\x18\x61\0\0\0\0\0\0\0\0\0\0\x18\x0f\0\0\x7b\x01\0\0\0\0\0\0\xb7\x01\0\0\x02\0\
\0\0\x18\x62\0\0\0\0\0\0\0\0\0\0\x08\x0f\0\0\xb7\x03\0\0\x20\0\0\0\x85\0\0\0\
\xa6\0\0\0\xbf\x07\0\0\0\0\0\0\xc5\x07\x9f\xff\0\0\0\0\x18\x62\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\x61\x20\0\0\0\0\0\0\x18\x61\0\0\0\0\0\0\0\0\0\0\x28\x0f\0\0\x63\
\x01\0\0\0\0\0\0\xb7\x01\0\0\x16\0\0\0\x18\x62\0\0\0\0\0\0\0\0\0\0\x28\x0f\0\0\
\xb7\x03\0\0\x04\0\0\0\x85\0\0\0\xa6\0\0\0\xbf\x07\0\0\0\0\0\0\xc5\x07\x92\xff\
\0\0\0\0\x18\x60\0\0\0\0\0\0\0\0\0\0\x30\x0f\0\0\x18\x61\0\0\0\0\0\0\0\0\0\0\
\x78\x11\0\0\x7b\x01\0\0\0\0\0\0\x18\x60\0\0\0\0\0\0\0\0\0\0\x38\x0f\0\0\x18\
\x61\0\0\0\0\0\0\0\0\0\0\x70\x11\0\0\x7b\x01\0\0\0\0\0\0\x18\x60\0\0\0\0\0\0\0\
\0\0\0\x40\x10\0\0\x18\x61\0\0\0\0\0\0\0\0\0\0\xb8\x11\0\0\x7b\x01\0\0\0\0\0\0\
\x18\x60\0\0\0\0\0\0\0\0\0\0\x48\x10\0\0\x18\x61\0\0\0\0\0\0\0\0\0\0\xc8\x11\0\
\0\x7b\x01\0\0\0\0\0\0\x18\x60\0\0\0\0\0\0\0\0\0\0\xe8\x10\0\0\x18\x61\0\0\0\0\
\0\0\0\0\0\0\xe8\x11\0\0\x7b\x01\0\0\0\0\0\0\x18\x60\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\x18\x61\0\0\0\0\0\0\0\0\0\0\xe0\x11\0\0\x7b\x01\0\0\0\0\0\0\x61\x60\x08\0\0\
\0\0\0\x18\x61\0\0\0\0\0\0\0\0\0\0\x80\x11\0\0\x63\x01\0\0\0\0\0\0\x61\x60\x0c\
\0\0\0\0\0\x18\x61\0\0\0\0\0\0\0\0\0\0\x84\x11\0\0\x63\x01\0\0\0\0\0\0\x79\x60\
\x10\0\0\0\0\0\x18\x61\0\0\0\0\0\0\0\0\0\0\x88\x11\0\0\x7b\x01\0\0\0\0\0\0\x61\
\xa0\x78\xff\0\0\0\0\x18\x61\0\0\0\0\0\0\0\0\0\0\xb0\x11\0\0\x63\x01\0\0\0\0\0\
\0\x18\x61\0\0\0\0\0\0\0\0\0\0\xf8\x11\0\0\xb7\x02\0\0\x11\0\0\0\xb7\x03\0\0\
\x0c\0\0\0\xb7\x04\0\0\0\0\0\0\x85\0\0\0\xa7\0\0\0\xbf\x07\0\0\0\0\0\0\xc5\x07\
\x5c\xff\0\0\0\0\x18\x60\0\0\0\0\0\0\0\0\0\0\x68\x11\0\0\x63\x70\x6c\0\0\0\0\0\
\x77\x07\0\0\x20\0\0\0\x63\x70\x70\0\0\0\0\0\xb7\x01\0\0\x05\0\0\0\x18\x62\0\0\
\0\0\0\0\0\0\0\0\x68\x11\0\0\xb7\x03\0\0\x8c\0\0\0\x85\0\0\0\xa6\0\0\0\xbf\x07\
\0\0\0\0\0\0\x18\x60\0\0\0\0\0\0\0\0\0\0\xd8\x11\0\0\x61\x01\0\0\0\0\0\0\xd5\
\x01\x02\0\0\0\0\0\xbf\x19\0\0\0\0\0\0\x85\0\0\0\xa8\0\0\0\xc5\x07\x4a\xff\0\0\
\0\0\x63\x7a\x80\xff\0\0\0\0\x18\x60\0\0\0\0\0\0\0\0\0\0\x10\x12\0\0\x18\x61\0\
\0\0\0\0\0\0\0\0\0\x10\x17\0\0\x7b\x01\0\0\0\0\0\0\x18\x60\0\0\0\0\0\0\0\0\0\0\
\x18\x12\0\0\x18\x61\0\0\0\0\0\0\0\0\0\0\x08\x17\0\0\x7b\x01\0\0\0\0\0\0\x18\
\x60\0\0\0\0\0\0\0\0\0\0\x28\x14\0\0\x18\x61\0\0\0\0\0\0\0\0\0\0\x50\x17\0\0\
\x7b\x01\0\0\0\0\0\0\x18\x60\0\0\0\0\0\0\0\0\0\0\x30\x14\0\0\x18\x61\0\0\0\0\0\
\0\0\0\0\0\x60\x17\0\0\x7b\x01\0\0\0\0\0\0\x18\x60\0\0\0\0\0\0\0\0\0\0\xd0\x15\
\0\0\x18\x61\0\0\0\0\0\0\0\0\0\0\x80\x17\0\0\x7b\x01\0\0\0\0\0\0\x18\x60\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\x18\x61\0\0\0\0\0\0\0\0\0\0\x78\x17\0\0\x7b\x01\0\0\0\0\
\0\0\x61\x60\x08\0\0\0\0\0\x18\x61\0\0\0\0\0\0\0\0\0\0\x18\x17\0\0\x63\x01\0\0\
\0\0\0\0\x61\x60\x0c\0\0\0\0\0\x18\x61\0\0\0\0\0\0\0\0\0\0\x1c\x17\0\0\x63\x01\
\0\0\0\0\0\0\x79\x60\x10\0\0\0\0\0\x18\x61\0\0\0\0\0\0\0\0\0\0\x20\x17\0\0\x7b\
\x01\0\0\0\0\0\0\x61\xa0\x78\xff\0\0\0\0\x18\x61\0\0\0\0\0\0\0\0\0\0\x48\x17\0\
\0\x63\x01\0\0\0\0\0\0\x18\x61\0\0\0\0\0\0\0\0\0\0\x90\x17\0\0\xb7\x02\0\0\x12\
\0\0\0\xb7\x03\0\0\x0c\0\0\0\xb7\x04\0\0\0\0\0\0\x85\0\0\0\xa7\0\0\0\xbf\x07\0\
\0\0\0\0\0\xc5\x07\x13\xff\0\0\0\0\x18\x60\0\0\0\0\0\0\0\0\0\0\0\x17\0\0\x63\
\x70\x6c\0\0\0\0\0\x77\x07\0\0\x20\0\0\0\x63\x70\x70\0\0\0\0\0\xb7\x01\0\0\x05\
\0\0\0\x18\x62\0\0\0\0\0\0\0\0\0\0\0\x17\0\0\xb7\x03\0\0\x8c\0\0\0\x85\0\0\0\
\xa6\0\0\0\xbf\x07\0\0\0\0\0\0\x18\x60\0\0\0\0\0\0\0\0\0\0\x70\x17\0\0\x61\x01\
\0\0\0\0\0\0\xd5\x01\x02\0\0\0\0\0\xbf\x19\0\0\0\0\0\0\x85\0\0\0\xa8\0\0\0\xc5\
\x07\x01\xff\0\0\0\0\x63\x7a\x84\xff\0\0\0\0\x61\xa1\x78\xff\0\0\0\0\xd5\x01\
\x02\0\0\0\0\0\xbf\x19\0\0\0\0\0\0\x85\0\0\0\xa8\0\0\0\x61\xa0\x80\xff\0\0\0\0\
\x63\x06\x28\0\0\0\0\0\x61\xa0\x84\xff\0\0\0\0\x63\x06\x2c\0\0\0\0\0\x18\x61\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\x61\x10\0\0\0\0\0\0\x63\x06\x18\0\0\0\0\0\xb7\0\0\0\
\0\0\0\0\x95\0\0\0\0\0\0\0";
	err = bpf_load_and_run(&opts);
	if (err < 0)
		return err;
	skel->rodata = skel_finalize_map_data(&skel->maps.rodata.initial_value,
					4096, PROT_READ, skel->maps.rodata.map_fd);
	if (!skel->rodata)
		return -ENOMEM;
	return 0;
}

static inline struct iterators_bpf *
iterators_bpf__open_and_load(void)
{
	struct iterators_bpf *skel;

	skel = iterators_bpf__open();
	if (!skel)
		return NULL;
	if (iterators_bpf__load(skel)) {
		iterators_bpf__destroy(skel);
		return NULL;
	}
	return skel;
}

#endif /* __ITERATORS_BPF_SKEL_H__ */
