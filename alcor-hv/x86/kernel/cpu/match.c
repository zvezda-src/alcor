#include <asm/cpu_device_id.h>
#include <asm/cpufeature.h>
#include <linux/cpu.h>
#include <linux/export.h>
#include <linux/slab.h>

const struct x86_cpu_id *x86_match_cpu(const struct x86_cpu_id *match)
{
	const struct x86_cpu_id *m;
	struct cpuinfo_x86 *c = &boot_cpu_data;

	for (m = match;
	     m->vendor | m->family | m->model | m->steppings | m->feature;
	     m++) {
		if (m->vendor != X86_VENDOR_ANY && c->x86_vendor != m->vendor)
			continue;
		if (m->family != X86_FAMILY_ANY && c->x86 != m->family)
			continue;
		if (m->model != X86_MODEL_ANY && c->x86_model != m->model)
			continue;
		if (m->steppings != X86_STEPPING_ANY &&
		    !(BIT(c->x86_stepping) & m->steppings))
			continue;
		if (m->feature != X86_FEATURE_ANY && !cpu_has(c, m->feature))
			continue;
		return m;
	}
	return NULL;
}
EXPORT_SYMBOL(x86_match_cpu);

static const struct x86_cpu_desc *
x86_match_cpu_with_stepping(const struct x86_cpu_desc *match)
{
	struct cpuinfo_x86 *c = &boot_cpu_data;
	const struct x86_cpu_desc *m;

	for (m = match; m->x86_family | m->x86_model; m++) {
		if (c->x86_vendor != m->x86_vendor)
			continue;
		if (c->x86 != m->x86_family)
			continue;
		if (c->x86_model != m->x86_model)
			continue;
		if (c->x86_stepping != m->x86_stepping)
			continue;
		return m;
	}
	return NULL;
}

bool x86_cpu_has_min_microcode_rev(const struct x86_cpu_desc *table)
{
	const struct x86_cpu_desc *res = x86_match_cpu_with_stepping(table);

	if (!res || res->x86_microcode_rev > boot_cpu_data.microcode)
		return false;

	return true;
}
EXPORT_SYMBOL_GPL(x86_cpu_has_min_microcode_rev);
