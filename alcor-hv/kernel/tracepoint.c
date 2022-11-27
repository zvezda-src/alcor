#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/types.h>
#include <linux/jhash.h>
#include <linux/list.h>
#include <linux/rcupdate.h>
#include <linux/tracepoint.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/static_key.h>

enum tp_func_state {
	TP_FUNC_0,
	TP_FUNC_1,
	TP_FUNC_2,
	TP_FUNC_N,
};

extern tracepoint_ptr_t __start___tracepoints_ptrs[];
extern tracepoint_ptr_t __stop___tracepoints_ptrs[];

DEFINE_SRCU(tracepoint_srcu);
EXPORT_SYMBOL_GPL(tracepoint_srcu);

enum tp_transition_sync {
	TP_TRANSITION_SYNC_1_0_1,
	TP_TRANSITION_SYNC_N_2_1,

	_NR_TP_TRANSITION_SYNC,
};

struct tp_transition_snapshot {
	unsigned long rcu;
	unsigned long srcu;
	bool ongoing;
};

static struct tp_transition_snapshot tp_transition_snapshot[_NR_TP_TRANSITION_SYNC];

static void tp_rcu_get_state(enum tp_transition_sync sync)
{
	struct tp_transition_snapshot *snapshot = &tp_transition_snapshot[sync];

	/* Keep the latest get_state snapshot. */
	snapshot->rcu = get_state_synchronize_rcu();
	snapshot->srcu = start_poll_synchronize_srcu(&tracepoint_srcu);
	snapshot->ongoing = true;
}

static void tp_rcu_cond_sync(enum tp_transition_sync sync)
{
	struct tp_transition_snapshot *snapshot = &tp_transition_snapshot[sync];

	if (!snapshot->ongoing)
		return;
	cond_synchronize_rcu(snapshot->rcu);
	if (!poll_state_synchronize_srcu(&tracepoint_srcu, snapshot->srcu))
		synchronize_srcu(&tracepoint_srcu);
	snapshot->ongoing = false;
}

static const int tracepoint_debug;

#ifdef CONFIG_MODULES
static DEFINE_MUTEX(tracepoint_module_list_mutex);

static LIST_HEAD(tracepoint_module_list);
#endif /* CONFIG_MODULES */

static DEFINE_MUTEX(tracepoints_mutex);

static struct rcu_head *early_probes;
static bool ok_to_free_tracepoints;

struct tp_probes {
	struct rcu_head rcu;
	struct tracepoint_func probes[];
};

static void tp_stub_func(void)
{
	return;
}

static inline void *allocate_probes(int count)
{
	struct tp_probes *p  = kmalloc(struct_size(p, probes, count),
				       GFP_KERNEL);
	return p == NULL ? NULL : p->probes;
}

static void srcu_free_old_probes(struct rcu_head *head)
{
	kfree(container_of(head, struct tp_probes, rcu));
}

static void rcu_free_old_probes(struct rcu_head *head)
{
	call_srcu(&tracepoint_srcu, head, srcu_free_old_probes);
}

static __init int release_early_probes(void)
{
	struct rcu_head *tmp;

	ok_to_free_tracepoints = true;

	while (early_probes) {
		tmp = early_probes;
		early_probes = tmp->next;
		call_rcu(tmp, rcu_free_old_probes);
	}

	return 0;
}

postcore_initcall(release_early_probes);

static inline void release_probes(struct tracepoint_func *old)
{
	if (old) {
		struct tp_probes *tp_probes = container_of(old,
			struct tp_probes, probes[0]);

		/*
		if (unlikely(!ok_to_free_tracepoints)) {
			tp_probes->rcu.next = early_probes;
			early_probes = &tp_probes->rcu;
			return;
		}

		/*
		call_rcu(&tp_probes->rcu, rcu_free_old_probes);
	}
}

static void debug_print_probes(struct tracepoint_func *funcs)
{
	int i;

	if (!tracepoint_debug || !funcs)
		return;

	for (i = 0; funcs[i].func; i++)
		printk(KERN_DEBUG "Probe %d : %p\n", i, funcs[i].func);
}

static struct tracepoint_func *
func_add(struct tracepoint_func **funcs, struct tracepoint_func *tp_func,
	 int prio)
{
	struct tracepoint_func *old, *new;
	int iter_probes;	/* Iterate over old probe array. */
	int nr_probes = 0;	/* Counter for probes */
	int pos = -1;		/* Insertion position into new array */

	if (WARN_ON(!tp_func->func))
		return ERR_PTR(-EINVAL);

	debug_print_probes(*funcs);
	old = *funcs;
	if (old) {
		/* (N -> N+1), (N != 0, 1) probes */
		for (iter_probes = 0; old[iter_probes].func; iter_probes++) {
			if (old[iter_probes].func == tp_stub_func)
				continue;	/* Skip stub functions. */
			if (old[iter_probes].func == tp_func->func &&
			    old[iter_probes].data == tp_func->data)
				return ERR_PTR(-EEXIST);
			nr_probes++;
		}
	}
	/* + 2 : one for new probe, one for NULL func */
	new = allocate_probes(nr_probes + 2);
	if (new == NULL)
		return ERR_PTR(-ENOMEM);
	if (old) {
		nr_probes = 0;
		for (iter_probes = 0; old[iter_probes].func; iter_probes++) {
			if (old[iter_probes].func == tp_stub_func)
				continue;
			/* Insert before probes of lower priority */
			if (pos < 0 && old[iter_probes].prio < prio)
				pos = nr_probes++;
			new[nr_probes++] = old[iter_probes];
		}
		if (pos < 0)
			pos = nr_probes++;
		/* nr_probes now points to the end of the new array */
	} else {
		pos = 0;
		nr_probes = 1; /* must point at end of array */
	}
	new[pos] = *tp_func;
	new[nr_probes].func = NULL;
	debug_print_probes(*funcs);
	return old;
}

static void *func_remove(struct tracepoint_func **funcs,
		struct tracepoint_func *tp_func)
{
	int nr_probes = 0, nr_del = 0, i;
	struct tracepoint_func *old, *new;

	old = *funcs;

	if (!old)
		return ERR_PTR(-ENOENT);

	debug_print_probes(*funcs);
	/* (N -> M), (N > 1, M >= 0) probes */
	if (tp_func->func) {
		for (nr_probes = 0; old[nr_probes].func; nr_probes++) {
			if ((old[nr_probes].func == tp_func->func &&
			     old[nr_probes].data == tp_func->data) ||
			    old[nr_probes].func == tp_stub_func)
				nr_del++;
		}
	}

	/*
	if (nr_probes - nr_del == 0) {
		/* N -> 0, (N > 1) */
		*funcs = NULL;
		debug_print_probes(*funcs);
		return old;
	} else {
		int j = 0;
		/* N -> M, (N > 1, M > 0) */
		/* + 1 for NULL */
		new = allocate_probes(nr_probes - nr_del + 1);
		if (new) {
			for (i = 0; old[i].func; i++) {
				if ((old[i].func != tp_func->func ||
				     old[i].data != tp_func->data) &&
				    old[i].func != tp_stub_func)
					new[j++] = old[i];
			}
			new[nr_probes - nr_del].func = NULL;
			*funcs = new;
		} else {
			/*
			for (i = 0; old[i].func; i++) {
				if (old[i].func == tp_func->func &&
				    old[i].data == tp_func->data)
					WRITE_ONCE(old[i].func, tp_stub_func);
			}
			*funcs = old;
		}
	}
	debug_print_probes(*funcs);
	return old;
}

static enum tp_func_state nr_func_state(const struct tracepoint_func *tp_funcs)
{
	if (!tp_funcs)
		return TP_FUNC_0;
	if (!tp_funcs[1].func)
		return TP_FUNC_1;
	if (!tp_funcs[2].func)
		return TP_FUNC_2;
	return TP_FUNC_N;	/* 3 or more */
}

static void tracepoint_update_call(struct tracepoint *tp, struct tracepoint_func *tp_funcs)
{
	void *func = tp->iterator;

	/* Synthetic events do not have static call sites */
	if (!tp->static_call_key)
		return;
	if (nr_func_state(tp_funcs) == TP_FUNC_1)
		func = tp_funcs[0].func;
	__static_call_update(tp->static_call_key, tp->static_call_tramp, func);
}

static int tracepoint_add_func(struct tracepoint *tp,
			       struct tracepoint_func *func, int prio,
			       bool warn)
{
	struct tracepoint_func *old, *tp_funcs;
	int ret;

	if (tp->regfunc && !static_key_enabled(&tp->key)) {
		ret = tp->regfunc();
		if (ret < 0)
			return ret;
	}

	tp_funcs = rcu_dereference_protected(tp->funcs,
			lockdep_is_held(&tracepoints_mutex));
	old = func_add(&tp_funcs, func, prio);
	if (IS_ERR(old)) {
		WARN_ON_ONCE(warn && PTR_ERR(old) != -ENOMEM);
		return PTR_ERR(old);
	}

	/*
	switch (nr_func_state(tp_funcs)) {
	case TP_FUNC_1:		/* 0->1 */
		/*
		tp_rcu_cond_sync(TP_TRANSITION_SYNC_1_0_1);
		/* Set static call to first function */
		tracepoint_update_call(tp, tp_funcs);
		/* Both iterator and static call handle NULL tp->funcs */
		rcu_assign_pointer(tp->funcs, tp_funcs);
		static_key_enable(&tp->key);
		break;
	case TP_FUNC_2:		/* 1->2 */
		/* Set iterator static call */
		tracepoint_update_call(tp, tp_funcs);
		/*
		fallthrough;
	case TP_FUNC_N:		/* N->N+1 (N>1) */
		rcu_assign_pointer(tp->funcs, tp_funcs);
		/*
		if (tp_funcs[0].data != old[0].data)
			tp_rcu_get_state(TP_TRANSITION_SYNC_N_2_1);
		break;
	default:
		WARN_ON_ONCE(1);
		break;
	}

	release_probes(old);
	return 0;
}

static int tracepoint_remove_func(struct tracepoint *tp,
		struct tracepoint_func *func)
{
	struct tracepoint_func *old, *tp_funcs;

	tp_funcs = rcu_dereference_protected(tp->funcs,
			lockdep_is_held(&tracepoints_mutex));
	old = func_remove(&tp_funcs, func);
	if (WARN_ON_ONCE(IS_ERR(old)))
		return PTR_ERR(old);

	if (tp_funcs == old)
		/* Failed allocating new tp_funcs, replaced func with stub */
		return 0;

	switch (nr_func_state(tp_funcs)) {
	case TP_FUNC_0:		/* 1->0 */
		/* Removed last function */
		if (tp->unregfunc && static_key_enabled(&tp->key))
			tp->unregfunc();

		static_key_disable(&tp->key);
		/* Set iterator static call */
		tracepoint_update_call(tp, tp_funcs);
		/* Both iterator and static call handle NULL tp->funcs */
		rcu_assign_pointer(tp->funcs, NULL);
		/*
		tp_rcu_get_state(TP_TRANSITION_SYNC_1_0_1);
		break;
	case TP_FUNC_1:		/* 2->1 */
		rcu_assign_pointer(tp->funcs, tp_funcs);
		/*
		if (tp_funcs[0].data != old[0].data)
			tp_rcu_get_state(TP_TRANSITION_SYNC_N_2_1);
		tp_rcu_cond_sync(TP_TRANSITION_SYNC_N_2_1);
		/* Set static call to first function */
		tracepoint_update_call(tp, tp_funcs);
		break;
	case TP_FUNC_2:		/* N->N-1 (N>2) */
		fallthrough;
	case TP_FUNC_N:
		rcu_assign_pointer(tp->funcs, tp_funcs);
		/*
		if (tp_funcs[0].data != old[0].data)
			tp_rcu_get_state(TP_TRANSITION_SYNC_N_2_1);
		break;
	default:
		WARN_ON_ONCE(1);
		break;
	}
	release_probes(old);
	return 0;
}

int tracepoint_probe_register_prio_may_exist(struct tracepoint *tp, void *probe,
					     void *data, int prio)
{
	struct tracepoint_func tp_func;
	int ret;

	mutex_lock(&tracepoints_mutex);
	tp_func.func = probe;
	tp_func.data = data;
	tp_func.prio = prio;
	ret = tracepoint_add_func(tp, &tp_func, prio, false);
	mutex_unlock(&tracepoints_mutex);
	return ret;
}
EXPORT_SYMBOL_GPL(tracepoint_probe_register_prio_may_exist);

int tracepoint_probe_register_prio(struct tracepoint *tp, void *probe,
				   void *data, int prio)
{
	struct tracepoint_func tp_func;
	int ret;

	mutex_lock(&tracepoints_mutex);
	tp_func.func = probe;
	tp_func.data = data;
	tp_func.prio = prio;
	ret = tracepoint_add_func(tp, &tp_func, prio, true);
	mutex_unlock(&tracepoints_mutex);
	return ret;
}
EXPORT_SYMBOL_GPL(tracepoint_probe_register_prio);

int tracepoint_probe_register(struct tracepoint *tp, void *probe, void *data)
{
	return tracepoint_probe_register_prio(tp, probe, data, TRACEPOINT_DEFAULT_PRIO);
}
EXPORT_SYMBOL_GPL(tracepoint_probe_register);

int tracepoint_probe_unregister(struct tracepoint *tp, void *probe, void *data)
{
	struct tracepoint_func tp_func;
	int ret;

	mutex_lock(&tracepoints_mutex);
	tp_func.func = probe;
	tp_func.data = data;
	ret = tracepoint_remove_func(tp, &tp_func);
	mutex_unlock(&tracepoints_mutex);
	return ret;
}
EXPORT_SYMBOL_GPL(tracepoint_probe_unregister);

static void for_each_tracepoint_range(
		tracepoint_ptr_t *begin, tracepoint_ptr_t *end,
		void (*fct)(struct tracepoint *tp, void *priv),
		void *priv)
{
	tracepoint_ptr_t *iter;

	if (!begin)
		return;
	for (iter = begin; iter < end; iter++)
		fct(tracepoint_ptr_deref(iter), priv);
}

#ifdef CONFIG_MODULES
bool trace_module_has_bad_taint(struct module *mod)
{
	return mod->taints & ~((1 << TAINT_OOT_MODULE) | (1 << TAINT_CRAP) |
			       (1 << TAINT_UNSIGNED_MODULE));
}

static BLOCKING_NOTIFIER_HEAD(tracepoint_notify_list);

int register_tracepoint_module_notifier(struct notifier_block *nb)
{
	struct tp_module *tp_mod;
	int ret;

	mutex_lock(&tracepoint_module_list_mutex);
	ret = blocking_notifier_chain_register(&tracepoint_notify_list, nb);
	if (ret)
		goto end;
	list_for_each_entry(tp_mod, &tracepoint_module_list, list)
		(void) nb->notifier_call(nb, MODULE_STATE_COMING, tp_mod);
end:
	mutex_unlock(&tracepoint_module_list_mutex);
	return ret;
}
EXPORT_SYMBOL_GPL(register_tracepoint_module_notifier);

int unregister_tracepoint_module_notifier(struct notifier_block *nb)
{
	struct tp_module *tp_mod;
	int ret;

	mutex_lock(&tracepoint_module_list_mutex);
	ret = blocking_notifier_chain_unregister(&tracepoint_notify_list, nb);
	if (ret)
		goto end;
	list_for_each_entry(tp_mod, &tracepoint_module_list, list)
		(void) nb->notifier_call(nb, MODULE_STATE_GOING, tp_mod);
end:
	mutex_unlock(&tracepoint_module_list_mutex);
	return ret;

}
EXPORT_SYMBOL_GPL(unregister_tracepoint_module_notifier);

static void tp_module_going_check_quiescent(struct tracepoint *tp, void *priv)
{
	WARN_ON_ONCE(tp->funcs);
}

static int tracepoint_module_coming(struct module *mod)
{
	struct tp_module *tp_mod;
	int ret = 0;

	if (!mod->num_tracepoints)
		return 0;

	/*
	if (trace_module_has_bad_taint(mod))
		return 0;
	mutex_lock(&tracepoint_module_list_mutex);
	tp_mod = kmalloc(sizeof(struct tp_module), GFP_KERNEL);
	if (!tp_mod) {
		ret = -ENOMEM;
		goto end;
	}
	tp_mod->mod = mod;
	list_add_tail(&tp_mod->list, &tracepoint_module_list);
	blocking_notifier_call_chain(&tracepoint_notify_list,
			MODULE_STATE_COMING, tp_mod);
end:
	mutex_unlock(&tracepoint_module_list_mutex);
	return ret;
}

static void tracepoint_module_going(struct module *mod)
{
	struct tp_module *tp_mod;

	if (!mod->num_tracepoints)
		return;

	mutex_lock(&tracepoint_module_list_mutex);
	list_for_each_entry(tp_mod, &tracepoint_module_list, list) {
		if (tp_mod->mod == mod) {
			blocking_notifier_call_chain(&tracepoint_notify_list,
					MODULE_STATE_GOING, tp_mod);
			list_del(&tp_mod->list);
			kfree(tp_mod);
			/*
			for_each_tracepoint_range(mod->tracepoints_ptrs,
				mod->tracepoints_ptrs + mod->num_tracepoints,
				tp_module_going_check_quiescent, NULL);
			break;
		}
	}
	/*
	mutex_unlock(&tracepoint_module_list_mutex);
}

static int tracepoint_module_notify(struct notifier_block *self,
		unsigned long val, void *data)
{
	struct module *mod = data;
	int ret = 0;

	switch (val) {
	case MODULE_STATE_COMING:
		ret = tracepoint_module_coming(mod);
		break;
	case MODULE_STATE_LIVE:
		break;
	case MODULE_STATE_GOING:
		tracepoint_module_going(mod);
		break;
	case MODULE_STATE_UNFORMED:
		break;
	}
	return notifier_from_errno(ret);
}

static struct notifier_block tracepoint_module_nb = {
	.notifier_call = tracepoint_module_notify,
	.priority = 0,
};

static __init int init_tracepoints(void)
{
	int ret;

	ret = register_module_notifier(&tracepoint_module_nb);
	if (ret)
		pr_warn("Failed to register tracepoint module enter notifier\n");

	return ret;
}
__initcall(init_tracepoints);
#endif /* CONFIG_MODULES */

void for_each_kernel_tracepoint(void (*fct)(struct tracepoint *tp, void *priv),
		void *priv)
{
	for_each_tracepoint_range(__start___tracepoints_ptrs,
		__stop___tracepoints_ptrs, fct, priv);
}
EXPORT_SYMBOL_GPL(for_each_kernel_tracepoint);

#ifdef CONFIG_HAVE_SYSCALL_TRACEPOINTS

static int sys_tracepoint_refcount;

int syscall_regfunc(void)
{
	struct task_struct *p, *t;

	if (!sys_tracepoint_refcount) {
		read_lock(&tasklist_lock);
		for_each_process_thread(p, t) {
			set_task_syscall_work(t, SYSCALL_TRACEPOINT);
		}
		read_unlock(&tasklist_lock);
	}
	sys_tracepoint_refcount++;

	return 0;
}

void syscall_unregfunc(void)
{
	struct task_struct *p, *t;

	sys_tracepoint_refcount--;
	if (!sys_tracepoint_refcount) {
		read_lock(&tasklist_lock);
		for_each_process_thread(p, t) {
			clear_task_syscall_work(t, SYSCALL_TRACEPOINT);
		}
		read_unlock(&tasklist_lock);
	}
}
#endif
