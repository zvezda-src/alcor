
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/kallsyms.h>
#include <linux/livepatch.h>
#include <linux/elf.h>
#include <linux/moduleloader.h>
#include <linux/completion.h>
#include <linux/memory.h>
#include <linux/rcupdate.h>
#include <asm/cacheflush.h>
#include "core.h"
#include "patch.h"
#include "state.h"
#include "transition.h"

DEFINE_MUTEX(klp_mutex);

LIST_HEAD(klp_patches);

static struct kobject *klp_root_kobj;

static bool klp_is_module(struct klp_object *obj)
{
	return obj->name;
}

static void klp_find_object_module(struct klp_object *obj)
{
	struct module *mod;

	if (!klp_is_module(obj))
		return;

	rcu_read_lock_sched();
	/*
	mod = find_module(obj->name);
	/*
	if (mod && mod->klp_alive)
		obj->mod = mod;

	rcu_read_unlock_sched();
}

static bool klp_initialized(void)
{
	return !!klp_root_kobj;
}

static struct klp_func *klp_find_func(struct klp_object *obj,
				      struct klp_func *old_func)
{
	struct klp_func *func;

	klp_for_each_func(obj, func) {
		if ((strcmp(old_func->old_name, func->old_name) == 0) &&
		    (old_func->old_sympos == func->old_sympos)) {
			return func;
		}
	}

	return NULL;
}

static struct klp_object *klp_find_object(struct klp_patch *patch,
					  struct klp_object *old_obj)
{
	struct klp_object *obj;

	klp_for_each_object(patch, obj) {
		if (klp_is_module(old_obj)) {
			if (klp_is_module(obj) &&
			    strcmp(old_obj->name, obj->name) == 0) {
				return obj;
			}
		} else if (!klp_is_module(obj)) {
			return obj;
		}
	}

	return NULL;
}

struct klp_find_arg {
	const char *objname;
	const char *name;
	unsigned long addr;
	unsigned long count;
	unsigned long pos;
};

static int klp_find_callback(void *data, const char *name,
			     struct module *mod, unsigned long addr)
{
	struct klp_find_arg *args = data;

	if ((mod && !args->objname) || (!mod && args->objname))
		return 0;

	if (strcmp(args->name, name))
		return 0;

	if (args->objname && strcmp(args->objname, mod->name))
		return 0;

	args->addr = addr;
	args->count++;

	/*
	if ((args->pos && (args->count == args->pos)) ||
	    (!args->pos && (args->count > 1)))
		return 1;

	return 0;
}

static int klp_find_object_symbol(const char *objname, const char *name,
				  unsigned long sympos, unsigned long *addr)
{
	struct klp_find_arg args = {
		.objname = objname,
		.name = name,
		.addr = 0,
		.count = 0,
		.pos = sympos,
	};

	if (objname)
		module_kallsyms_on_each_symbol(klp_find_callback, &args);
	else
		kallsyms_on_each_symbol(klp_find_callback, &args);

	/*
	if (args.addr == 0)
		pr_err("symbol '%s' not found in symbol table\n", name);
	else if (args.count > 1 && sympos == 0) {
		pr_err("unresolvable ambiguity for symbol '%s' in object '%s'\n",
		       name, objname);
	} else if (sympos != args.count && sympos > 0) {
		pr_err("symbol position %lu for symbol '%s' in object '%s' not found\n",
		       sympos, name, objname ? objname : "vmlinux");
	} else {
		*addr = args.addr;
		return 0;
	}

	return -EINVAL;
}

static int klp_resolve_symbols(Elf_Shdr *sechdrs, const char *strtab,
			       unsigned int symndx, Elf_Shdr *relasec,
			       const char *sec_objname)
{
	int i, cnt, ret;
	char sym_objname[MODULE_NAME_LEN];
	char sym_name[KSYM_NAME_LEN];
	Elf_Rela *relas;
	Elf_Sym *sym;
	unsigned long sympos, addr;
	bool sym_vmlinux;
	bool sec_vmlinux = !strcmp(sec_objname, "vmlinux");

	/*
	BUILD_BUG_ON(MODULE_NAME_LEN < 56 || KSYM_NAME_LEN != 128);

	relas = (Elf_Rela *) relasec->sh_addr;
	/* For each rela in this klp relocation section */
	for (i = 0; i < relasec->sh_size / sizeof(Elf_Rela); i++) {
		sym = (Elf_Sym *)sechdrs[symndx].sh_addr + ELF_R_SYM(relas[i].r_info);
		if (sym->st_shndx != SHN_LIVEPATCH) {
			pr_err("symbol %s is not marked as a livepatch symbol\n",
			       strtab + sym->st_name);
			return -EINVAL;
		}

		/* Format: .klp.sym.sym_objname.sym_name,sympos */
		cnt = sscanf(strtab + sym->st_name,
			     ".klp.sym.%55[^.].%127[^,],%lu",
			     sym_objname, sym_name, &sympos);
		if (cnt != 3) {
			pr_err("symbol %s has an incorrectly formatted name\n",
			       strtab + sym->st_name);
			return -EINVAL;
		}

		sym_vmlinux = !strcmp(sym_objname, "vmlinux");

		/*
		if (!sec_vmlinux && sym_vmlinux) {
			pr_err("invalid access to vmlinux symbol '%s' from module-specific livepatch relocation section",
			       sym_name);
			return -EINVAL;
		}

		/* klp_find_object_symbol() treats a NULL objname as vmlinux */
		ret = klp_find_object_symbol(sym_vmlinux ? NULL : sym_objname,
					     sym_name, sympos, &addr);
		if (ret)
			return ret;

		sym->st_value = addr;
	}

	return 0;
}

int klp_apply_section_relocs(struct module *pmod, Elf_Shdr *sechdrs,
			     const char *shstrtab, const char *strtab,
			     unsigned int symndx, unsigned int secndx,
			     const char *objname)
{
	int cnt, ret;
	char sec_objname[MODULE_NAME_LEN];
	Elf_Shdr *sec = sechdrs + secndx;

	/*
	cnt = sscanf(shstrtab + sec->sh_name, ".klp.rela.%55[^.]",
		     sec_objname);
	if (cnt != 1) {
		pr_err("section %s has an incorrectly formatted name\n",
		       shstrtab + sec->sh_name);
		return -EINVAL;
	}

	if (strcmp(objname ? objname : "vmlinux", sec_objname))
		return 0;

	ret = klp_resolve_symbols(sechdrs, strtab, symndx, sec, sec_objname);
	if (ret)
		return ret;

	return apply_relocate_add(sechdrs, strtab, symndx, secndx, pmod);
}

static int __klp_disable_patch(struct klp_patch *patch);

static ssize_t enabled_store(struct kobject *kobj, struct kobj_attribute *attr,
			     const char *buf, size_t count)
{
	struct klp_patch *patch;
	int ret;
	bool enabled;

	ret = kstrtobool(buf, &enabled);
	if (ret)
		return ret;

	patch = container_of(kobj, struct klp_patch, kobj);

	mutex_lock(&klp_mutex);

	if (patch->enabled == enabled) {
		/* already in requested state */
		ret = -EINVAL;
		goto out;
	}

	/*
	if (patch == klp_transition_patch)
		klp_reverse_transition();
	else if (!enabled)
		ret = __klp_disable_patch(patch);
	else
		ret = -EINVAL;

out:
	mutex_unlock(&klp_mutex);

	if (ret)
		return ret;
	return count;
}

static ssize_t enabled_show(struct kobject *kobj,
			    struct kobj_attribute *attr, char *buf)
{
	struct klp_patch *patch;

	patch = container_of(kobj, struct klp_patch, kobj);
	return snprintf(buf, PAGE_SIZE-1, "%d\n", patch->enabled);
}

static ssize_t transition_show(struct kobject *kobj,
			       struct kobj_attribute *attr, char *buf)
{
	struct klp_patch *patch;

	patch = container_of(kobj, struct klp_patch, kobj);
	return snprintf(buf, PAGE_SIZE-1, "%d\n",
			patch == klp_transition_patch);
}

static ssize_t force_store(struct kobject *kobj, struct kobj_attribute *attr,
			   const char *buf, size_t count)
{
	struct klp_patch *patch;
	int ret;
	bool val;

	ret = kstrtobool(buf, &val);
	if (ret)
		return ret;

	if (!val)
		return count;

	mutex_lock(&klp_mutex);

	patch = container_of(kobj, struct klp_patch, kobj);
	if (patch != klp_transition_patch) {
		mutex_unlock(&klp_mutex);
		return -EINVAL;
	}

	klp_force_transition();

	mutex_unlock(&klp_mutex);

	return count;
}

static struct kobj_attribute enabled_kobj_attr = __ATTR_RW(enabled);
static struct kobj_attribute transition_kobj_attr = __ATTR_RO(transition);
static struct kobj_attribute force_kobj_attr = __ATTR_WO(force);
static struct attribute *klp_patch_attrs[] = {
	&enabled_kobj_attr.attr,
	&transition_kobj_attr.attr,
	&force_kobj_attr.attr,
	NULL
};
ATTRIBUTE_GROUPS(klp_patch);

static void klp_free_object_dynamic(struct klp_object *obj)
{
	kfree(obj->name);
	kfree(obj);
}

static void klp_init_func_early(struct klp_object *obj,
				struct klp_func *func);
static void klp_init_object_early(struct klp_patch *patch,
				  struct klp_object *obj);

static struct klp_object *klp_alloc_object_dynamic(const char *name,
						   struct klp_patch *patch)
{
	struct klp_object *obj;

	obj = kzalloc(sizeof(*obj), GFP_KERNEL);
	if (!obj)
		return NULL;

	if (name) {
		obj->name = kstrdup(name, GFP_KERNEL);
		if (!obj->name) {
			kfree(obj);
			return NULL;
		}
	}

	klp_init_object_early(patch, obj);
	obj->dynamic = true;

	return obj;
}

static void klp_free_func_nop(struct klp_func *func)
{
	kfree(func->old_name);
	kfree(func);
}

static struct klp_func *klp_alloc_func_nop(struct klp_func *old_func,
					   struct klp_object *obj)
{
	struct klp_func *func;

	func = kzalloc(sizeof(*func), GFP_KERNEL);
	if (!func)
		return NULL;

	if (old_func->old_name) {
		func->old_name = kstrdup(old_func->old_name, GFP_KERNEL);
		if (!func->old_name) {
			kfree(func);
			return NULL;
		}
	}

	klp_init_func_early(obj, func);
	/*
	func->old_sympos = old_func->old_sympos;
	func->nop = true;

	return func;
}

static int klp_add_object_nops(struct klp_patch *patch,
			       struct klp_object *old_obj)
{
	struct klp_object *obj;
	struct klp_func *func, *old_func;

	obj = klp_find_object(patch, old_obj);

	if (!obj) {
		obj = klp_alloc_object_dynamic(old_obj->name, patch);
		if (!obj)
			return -ENOMEM;
	}

	klp_for_each_func(old_obj, old_func) {
		func = klp_find_func(obj, old_func);
		if (func)
			continue;

		func = klp_alloc_func_nop(old_func, obj);
		if (!func)
			return -ENOMEM;
	}

	return 0;
}

static int klp_add_nops(struct klp_patch *patch)
{
	struct klp_patch *old_patch;
	struct klp_object *old_obj;

	klp_for_each_patch(old_patch) {
		klp_for_each_object(old_patch, old_obj) {
			int err;

			err = klp_add_object_nops(patch, old_obj);
			if (err)
				return err;
		}
	}

	return 0;
}

static void klp_kobj_release_patch(struct kobject *kobj)
{
	struct klp_patch *patch;

	patch = container_of(kobj, struct klp_patch, kobj);
	complete(&patch->finish);
}

static struct kobj_type klp_ktype_patch = {
	.release = klp_kobj_release_patch,
	.sysfs_ops = &kobj_sysfs_ops,
	.default_groups = klp_patch_groups,
};

static void klp_kobj_release_object(struct kobject *kobj)
{
	struct klp_object *obj;

	obj = container_of(kobj, struct klp_object, kobj);

	if (obj->dynamic)
		klp_free_object_dynamic(obj);
}

static struct kobj_type klp_ktype_object = {
	.release = klp_kobj_release_object,
	.sysfs_ops = &kobj_sysfs_ops,
};

static void klp_kobj_release_func(struct kobject *kobj)
{
	struct klp_func *func;

	func = container_of(kobj, struct klp_func, kobj);

	if (func->nop)
		klp_free_func_nop(func);
}

static struct kobj_type klp_ktype_func = {
	.release = klp_kobj_release_func,
	.sysfs_ops = &kobj_sysfs_ops,
};

static void __klp_free_funcs(struct klp_object *obj, bool nops_only)
{
	struct klp_func *func, *tmp_func;

	klp_for_each_func_safe(obj, func, tmp_func) {
		if (nops_only && !func->nop)
			continue;

		list_del(&func->node);
		kobject_put(&func->kobj);
	}
}

static void klp_free_object_loaded(struct klp_object *obj)
{
	struct klp_func *func;

	obj->mod = NULL;

	klp_for_each_func(obj, func) {
		func->old_func = NULL;

		if (func->nop)
			func->new_func = NULL;
	}
}

static void __klp_free_objects(struct klp_patch *patch, bool nops_only)
{
	struct klp_object *obj, *tmp_obj;

	klp_for_each_object_safe(patch, obj, tmp_obj) {
		__klp_free_funcs(obj, nops_only);

		if (nops_only && !obj->dynamic)
			continue;

		list_del(&obj->node);
		kobject_put(&obj->kobj);
	}
}

static void klp_free_objects(struct klp_patch *patch)
{
	__klp_free_objects(patch, false);
}

static void klp_free_objects_dynamic(struct klp_patch *patch)
{
	__klp_free_objects(patch, true);
}

static void klp_free_patch_start(struct klp_patch *patch)
{
	if (!list_empty(&patch->list))
		list_del(&patch->list);

	klp_free_objects(patch);
}

static void klp_free_patch_finish(struct klp_patch *patch)
{
	/*
	kobject_put(&patch->kobj);
	wait_for_completion(&patch->finish);

	/* Put the module after the last access to struct klp_patch. */
	if (!patch->forced)
		module_put(patch->mod);
}

static void klp_free_patch_work_fn(struct work_struct *work)
{
	struct klp_patch *patch =
		container_of(work, struct klp_patch, free_work);

	klp_free_patch_finish(patch);
}

void klp_free_patch_async(struct klp_patch *patch)
{
	klp_free_patch_start(patch);
	schedule_work(&patch->free_work);
}

void klp_free_replaced_patches_async(struct klp_patch *new_patch)
{
	struct klp_patch *old_patch, *tmp_patch;

	klp_for_each_patch_safe(old_patch, tmp_patch) {
		if (old_patch == new_patch)
			return;
		klp_free_patch_async(old_patch);
	}
}

static int klp_init_func(struct klp_object *obj, struct klp_func *func)
{
	if (!func->old_name)
		return -EINVAL;

	/*
	if (!func->new_func && !func->nop)
		return -EINVAL;

	if (strlen(func->old_name) >= KSYM_NAME_LEN)
		return -EINVAL;

	INIT_LIST_HEAD(&func->stack_node);
	func->patched = false;
	func->transition = false;

	/* The format for the sysfs directory is <function,sympos> where sympos
	 * is the nth occurrence of this symbol in kallsyms for the patched
	 * object. If the user selects 0 for old_sympos, then 1 will be used
	 * since a unique symbol will be the first occurrence.
	 */
	return kobject_add(&func->kobj, &obj->kobj, "%s,%lu",
			   func->old_name,
			   func->old_sympos ? func->old_sympos : 1);
}

static int klp_apply_object_relocs(struct klp_patch *patch,
				   struct klp_object *obj)
{
	int i, ret;
	struct klp_modinfo *info = patch->mod->klp_info;

	for (i = 1; i < info->hdr.e_shnum; i++) {
		Elf_Shdr *sec = info->sechdrs + i;

		if (!(sec->sh_flags & SHF_RELA_LIVEPATCH))
			continue;

		ret = klp_apply_section_relocs(patch->mod, info->sechdrs,
					       info->secstrings,
					       patch->mod->core_kallsyms.strtab,
					       info->symndx, i, obj->name);
		if (ret)
			return ret;
	}

	return 0;
}

static int klp_init_object_loaded(struct klp_patch *patch,
				  struct klp_object *obj)
{
	struct klp_func *func;
	int ret;

	if (klp_is_module(obj)) {
		/*
		ret = klp_apply_object_relocs(patch, obj);
		if (ret)
			return ret;
	}

	klp_for_each_func(obj, func) {
		ret = klp_find_object_symbol(obj->name, func->old_name,
					     func->old_sympos,
					     (unsigned long *)&func->old_func);
		if (ret)
			return ret;

		ret = kallsyms_lookup_size_offset((unsigned long)func->old_func,
						  &func->old_size, NULL);
		if (!ret) {
			pr_err("kallsyms size lookup failed for '%s'\n",
			       func->old_name);
			return -ENOENT;
		}

		if (func->nop)
			func->new_func = func->old_func;

		ret = kallsyms_lookup_size_offset((unsigned long)func->new_func,
						  &func->new_size, NULL);
		if (!ret) {
			pr_err("kallsyms size lookup failed for '%s' replacement\n",
			       func->old_name);
			return -ENOENT;
		}
	}

	return 0;
}

static int klp_init_object(struct klp_patch *patch, struct klp_object *obj)
{
	struct klp_func *func;
	int ret;
	const char *name;

	if (klp_is_module(obj) && strlen(obj->name) >= MODULE_NAME_LEN)
		return -EINVAL;

	obj->patched = false;
	obj->mod = NULL;

	klp_find_object_module(obj);

	name = klp_is_module(obj) ? obj->name : "vmlinux";
	ret = kobject_add(&obj->kobj, &patch->kobj, "%s", name);
	if (ret)
		return ret;

	klp_for_each_func(obj, func) {
		ret = klp_init_func(obj, func);
		if (ret)
			return ret;
	}

	if (klp_is_object_loaded(obj))
		ret = klp_init_object_loaded(patch, obj);

	return ret;
}

static void klp_init_func_early(struct klp_object *obj,
				struct klp_func *func)
{
	kobject_init(&func->kobj, &klp_ktype_func);
	list_add_tail(&func->node, &obj->func_list);
}

static void klp_init_object_early(struct klp_patch *patch,
				  struct klp_object *obj)
{
	INIT_LIST_HEAD(&obj->func_list);
	kobject_init(&obj->kobj, &klp_ktype_object);
	list_add_tail(&obj->node, &patch->obj_list);
}

static void klp_init_patch_early(struct klp_patch *patch)
{
	struct klp_object *obj;
	struct klp_func *func;

	INIT_LIST_HEAD(&patch->list);
	INIT_LIST_HEAD(&patch->obj_list);
	kobject_init(&patch->kobj, &klp_ktype_patch);
	patch->enabled = false;
	patch->forced = false;
	INIT_WORK(&patch->free_work, klp_free_patch_work_fn);
	init_completion(&patch->finish);

	klp_for_each_object_static(patch, obj) {
		klp_init_object_early(patch, obj);

		klp_for_each_func_static(obj, func) {
			klp_init_func_early(obj, func);
		}
	}
}

static int klp_init_patch(struct klp_patch *patch)
{
	struct klp_object *obj;
	int ret;

	ret = kobject_add(&patch->kobj, klp_root_kobj, "%s", patch->mod->name);
	if (ret)
		return ret;

	if (patch->replace) {
		ret = klp_add_nops(patch);
		if (ret)
			return ret;
	}

	klp_for_each_object(patch, obj) {
		ret = klp_init_object(patch, obj);
		if (ret)
			return ret;
	}

	list_add_tail(&patch->list, &klp_patches);

	return 0;
}

static int __klp_disable_patch(struct klp_patch *patch)
{
	struct klp_object *obj;

	if (WARN_ON(!patch->enabled))
		return -EINVAL;

	if (klp_transition_patch)
		return -EBUSY;

	klp_init_transition(patch, KLP_UNPATCHED);

	klp_for_each_object(patch, obj)
		if (obj->patched)
			klp_pre_unpatch_callback(obj);

	/*
	smp_wmb();

	klp_start_transition();
	patch->enabled = false;
	klp_try_complete_transition();

	return 0;
}

static int __klp_enable_patch(struct klp_patch *patch)
{
	struct klp_object *obj;
	int ret;

	if (klp_transition_patch)
		return -EBUSY;

	if (WARN_ON(patch->enabled))
		return -EINVAL;

	pr_notice("enabling patch '%s'\n", patch->mod->name);

	klp_init_transition(patch, KLP_PATCHED);

	/*
	smp_wmb();

	klp_for_each_object(patch, obj) {
		if (!klp_is_object_loaded(obj))
			continue;

		ret = klp_pre_patch_callback(obj);
		if (ret) {
			pr_warn("pre-patch callback failed for object '%s'\n",
				klp_is_module(obj) ? obj->name : "vmlinux");
			goto err;
		}

		ret = klp_patch_object(obj);
		if (ret) {
			pr_warn("failed to patch object '%s'\n",
				klp_is_module(obj) ? obj->name : "vmlinux");
			goto err;
		}
	}

	klp_start_transition();
	patch->enabled = true;
	klp_try_complete_transition();

	return 0;
err:
	pr_warn("failed to enable patch '%s'\n", patch->mod->name);

	klp_cancel_transition();
	return ret;
}

int klp_enable_patch(struct klp_patch *patch)
{
	int ret;
	struct klp_object *obj;

	if (!patch || !patch->mod || !patch->objs)
		return -EINVAL;

	klp_for_each_object_static(patch, obj) {
		if (!obj->funcs)
			return -EINVAL;
	}


	if (!is_livepatch_module(patch->mod)) {
		pr_err("module %s is not marked as a livepatch module\n",
		       patch->mod->name);
		return -EINVAL;
	}

	if (!klp_initialized())
		return -ENODEV;

	if (!klp_have_reliable_stack()) {
		pr_warn("This architecture doesn't have support for the livepatch consistency model.\n");
		pr_warn("The livepatch transition may never complete.\n");
	}

	mutex_lock(&klp_mutex);

	if (!klp_is_patch_compatible(patch)) {
		pr_err("Livepatch patch (%s) is not compatible with the already installed livepatches.\n",
			patch->mod->name);
		mutex_unlock(&klp_mutex);
		return -EINVAL;
	}

	if (!try_module_get(patch->mod)) {
		mutex_unlock(&klp_mutex);
		return -ENODEV;
	}

	klp_init_patch_early(patch);

	ret = klp_init_patch(patch);
	if (ret)
		goto err;

	ret = __klp_enable_patch(patch);
	if (ret)
		goto err;

	mutex_unlock(&klp_mutex);

	return 0;

err:
	klp_free_patch_start(patch);

	mutex_unlock(&klp_mutex);

	klp_free_patch_finish(patch);

	return ret;
}
EXPORT_SYMBOL_GPL(klp_enable_patch);

void klp_unpatch_replaced_patches(struct klp_patch *new_patch)
{
	struct klp_patch *old_patch;

	klp_for_each_patch(old_patch) {
		if (old_patch == new_patch)
			return;

		old_patch->enabled = false;
		klp_unpatch_objects(old_patch);
	}
}

void klp_discard_nops(struct klp_patch *new_patch)
{
	klp_unpatch_objects_dynamic(klp_transition_patch);
	klp_free_objects_dynamic(klp_transition_patch);
}

static void klp_cleanup_module_patches_limited(struct module *mod,
					       struct klp_patch *limit)
{
	struct klp_patch *patch;
	struct klp_object *obj;

	klp_for_each_patch(patch) {
		if (patch == limit)
			break;

		klp_for_each_object(patch, obj) {
			if (!klp_is_module(obj) || strcmp(obj->name, mod->name))
				continue;

			if (patch != klp_transition_patch)
				klp_pre_unpatch_callback(obj);

			pr_notice("reverting patch '%s' on unloading module '%s'\n",
				  patch->mod->name, obj->mod->name);
			klp_unpatch_object(obj);

			klp_post_unpatch_callback(obj);

			klp_free_object_loaded(obj);
			break;
		}
	}
}

int klp_module_coming(struct module *mod)
{
	int ret;
	struct klp_patch *patch;
	struct klp_object *obj;

	if (WARN_ON(mod->state != MODULE_STATE_COMING))
		return -EINVAL;

	if (!strcmp(mod->name, "vmlinux")) {
		pr_err("vmlinux.ko: invalid module name");
		return -EINVAL;
	}

	mutex_lock(&klp_mutex);
	/*
	mod->klp_alive = true;

	klp_for_each_patch(patch) {
		klp_for_each_object(patch, obj) {
			if (!klp_is_module(obj) || strcmp(obj->name, mod->name))
				continue;

			obj->mod = mod;

			ret = klp_init_object_loaded(patch, obj);
			if (ret) {
				pr_warn("failed to initialize patch '%s' for module '%s' (%d)\n",
					patch->mod->name, obj->mod->name, ret);
				goto err;
			}

			pr_notice("applying patch '%s' to loading module '%s'\n",
				  patch->mod->name, obj->mod->name);

			ret = klp_pre_patch_callback(obj);
			if (ret) {
				pr_warn("pre-patch callback failed for object '%s'\n",
					obj->name);
				goto err;
			}

			ret = klp_patch_object(obj);
			if (ret) {
				pr_warn("failed to apply patch '%s' to module '%s' (%d)\n",
					patch->mod->name, obj->mod->name, ret);

				klp_post_unpatch_callback(obj);
				goto err;
			}

			if (patch != klp_transition_patch)
				klp_post_patch_callback(obj);

			break;
		}
	}

	mutex_unlock(&klp_mutex);

	return 0;

err:
	/*
	pr_warn("patch '%s' failed for module '%s', refusing to load module '%s'\n",
		patch->mod->name, obj->mod->name, obj->mod->name);
	mod->klp_alive = false;
	obj->mod = NULL;
	klp_cleanup_module_patches_limited(mod, patch);
	mutex_unlock(&klp_mutex);

	return ret;
}

void klp_module_going(struct module *mod)
{
	if (WARN_ON(mod->state != MODULE_STATE_GOING &&
		    mod->state != MODULE_STATE_COMING))
		return;

	mutex_lock(&klp_mutex);
	/*
	mod->klp_alive = false;

	klp_cleanup_module_patches_limited(mod, NULL);

	mutex_unlock(&klp_mutex);
}

static int __init klp_init(void)
{
	klp_root_kobj = kobject_create_and_add("livepatch", kernel_kobj);
	if (!klp_root_kobj)
		return -ENOMEM;

	return 0;
}

module_init(klp_init);
