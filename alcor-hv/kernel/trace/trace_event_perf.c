
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/security.h>
#include "trace.h"
#include "trace_probe.h"

static char __percpu *perf_trace_buf[PERF_NR_CONTEXTS];

typedef typeof(unsigned long [PERF_MAX_TRACE_SIZE / sizeof(unsigned long)])
	perf_trace_t;

static int	total_ref_count;

static int perf_trace_event_perm(struct trace_event_call *tp_event,
				 struct perf_event *p_event)
{
	int ret;

	if (tp_event->perf_perm) {
		ret = tp_event->perf_perm(tp_event, p_event);
		if (ret)
			return ret;
	}

	/*
	if (p_event->parent)
		return 0;

	/*

	/* The ftrace function trace is allowed only for root. */
	if (ftrace_event_is_function(tp_event)) {
		ret = perf_allow_tracepoint(&p_event->attr);
		if (ret)
			return ret;

		if (!is_sampling_event(p_event))
			return 0;

		/*
		if (!p_event->attr.exclude_callchain_user)
			return -EINVAL;

		/*
		if (p_event->attr.sample_type & PERF_SAMPLE_STACK_USER)
			return -EINVAL;
	}

	/* No tracing, just counting, so no obvious leak */
	if (!(p_event->attr.sample_type & PERF_SAMPLE_RAW))
		return 0;

	/* Some events are ok to be traced by non-root users... */
	if (p_event->attach_state == PERF_ATTACH_TASK) {
		if (tp_event->flags & TRACE_EVENT_FL_CAP_ANY)
			return 0;
	}

	/*
	ret = perf_allow_tracepoint(&p_event->attr);
	if (ret)
		return ret;

	return 0;
}

static int perf_trace_event_reg(struct trace_event_call *tp_event,
				struct perf_event *p_event)
{
	struct hlist_head __percpu *list;
	int ret = -ENOMEM;
	int cpu;

	p_event->tp_event = tp_event;
	if (tp_event->perf_refcount++ > 0)
		return 0;

	list = alloc_percpu(struct hlist_head);
	if (!list)
		goto fail;

	for_each_possible_cpu(cpu)
		INIT_HLIST_HEAD(per_cpu_ptr(list, cpu));

	tp_event->perf_events = list;

	if (!total_ref_count) {
		char __percpu *buf;
		int i;

		for (i = 0; i < PERF_NR_CONTEXTS; i++) {
			buf = (char __percpu *)alloc_percpu(perf_trace_t);
			if (!buf)
				goto fail;

			perf_trace_buf[i] = buf;
		}
	}

	ret = tp_event->class->reg(tp_event, TRACE_REG_PERF_REGISTER, NULL);
	if (ret)
		goto fail;

	total_ref_count++;
	return 0;

fail:
	if (!total_ref_count) {
		int i;

		for (i = 0; i < PERF_NR_CONTEXTS; i++) {
			free_percpu(perf_trace_buf[i]);
			perf_trace_buf[i] = NULL;
		}
	}

	if (!--tp_event->perf_refcount) {
		free_percpu(tp_event->perf_events);
		tp_event->perf_events = NULL;
	}

	return ret;
}

static void perf_trace_event_unreg(struct perf_event *p_event)
{
	struct trace_event_call *tp_event = p_event->tp_event;
	int i;

	if (--tp_event->perf_refcount > 0)
		goto out;

	tp_event->class->reg(tp_event, TRACE_REG_PERF_UNREGISTER, NULL);

	/*
	tracepoint_synchronize_unregister();

	free_percpu(tp_event->perf_events);
	tp_event->perf_events = NULL;

	if (!--total_ref_count) {
		for (i = 0; i < PERF_NR_CONTEXTS; i++) {
			free_percpu(perf_trace_buf[i]);
			perf_trace_buf[i] = NULL;
		}
	}
out:
	trace_event_put_ref(tp_event);
}

static int perf_trace_event_open(struct perf_event *p_event)
{
	struct trace_event_call *tp_event = p_event->tp_event;
	return tp_event->class->reg(tp_event, TRACE_REG_PERF_OPEN, p_event);
}

static void perf_trace_event_close(struct perf_event *p_event)
{
	struct trace_event_call *tp_event = p_event->tp_event;
	tp_event->class->reg(tp_event, TRACE_REG_PERF_CLOSE, p_event);
}

static int perf_trace_event_init(struct trace_event_call *tp_event,
				 struct perf_event *p_event)
{
	int ret;

	ret = perf_trace_event_perm(tp_event, p_event);
	if (ret)
		return ret;

	ret = perf_trace_event_reg(tp_event, p_event);
	if (ret)
		return ret;

	ret = perf_trace_event_open(p_event);
	if (ret) {
		perf_trace_event_unreg(p_event);
		return ret;
	}

	return 0;
}

int perf_trace_init(struct perf_event *p_event)
{
	struct trace_event_call *tp_event;
	u64 event_id = p_event->attr.config;
	int ret = -EINVAL;

	mutex_lock(&event_mutex);
	list_for_each_entry(tp_event, &ftrace_events, list) {
		if (tp_event->event.type == event_id &&
		    tp_event->class && tp_event->class->reg &&
		    trace_event_try_get_ref(tp_event)) {
			ret = perf_trace_event_init(tp_event, p_event);
			if (ret)
				trace_event_put_ref(tp_event);
			break;
		}
	}
	mutex_unlock(&event_mutex);

	return ret;
}

void perf_trace_destroy(struct perf_event *p_event)
{
	mutex_lock(&event_mutex);
	perf_trace_event_close(p_event);
	perf_trace_event_unreg(p_event);
	mutex_unlock(&event_mutex);
}

#ifdef CONFIG_KPROBE_EVENTS
int perf_kprobe_init(struct perf_event *p_event, bool is_retprobe)
{
	int ret;
	char *func = NULL;
	struct trace_event_call *tp_event;

	if (p_event->attr.kprobe_func) {
		func = kzalloc(KSYM_NAME_LEN, GFP_KERNEL);
		if (!func)
			return -ENOMEM;
		ret = strncpy_from_user(
			func, u64_to_user_ptr(p_event->attr.kprobe_func),
			KSYM_NAME_LEN);
		if (ret == KSYM_NAME_LEN)
			ret = -E2BIG;
		if (ret < 0)
			goto out;

		if (func[0] == '\0') {
			kfree(func);
			func = NULL;
		}
	}

	tp_event = create_local_trace_kprobe(
		func, (void *)(unsigned long)(p_event->attr.kprobe_addr),
		p_event->attr.probe_offset, is_retprobe);
	if (IS_ERR(tp_event)) {
		ret = PTR_ERR(tp_event);
		goto out;
	}

	mutex_lock(&event_mutex);
	ret = perf_trace_event_init(tp_event, p_event);
	if (ret)
		destroy_local_trace_kprobe(tp_event);
	mutex_unlock(&event_mutex);
out:
	kfree(func);
	return ret;
}

void perf_kprobe_destroy(struct perf_event *p_event)
{
	mutex_lock(&event_mutex);
	perf_trace_event_close(p_event);
	perf_trace_event_unreg(p_event);
	mutex_unlock(&event_mutex);

	destroy_local_trace_kprobe(p_event->tp_event);
}
#endif /* CONFIG_KPROBE_EVENTS */

#ifdef CONFIG_UPROBE_EVENTS
int perf_uprobe_init(struct perf_event *p_event,
		     unsigned long ref_ctr_offset, bool is_retprobe)
{
	int ret;
	char *path = NULL;
	struct trace_event_call *tp_event;

	if (!p_event->attr.uprobe_path)
		return -EINVAL;

	path = strndup_user(u64_to_user_ptr(p_event->attr.uprobe_path),
			    PATH_MAX);
	if (IS_ERR(path)) {
		ret = PTR_ERR(path);
		return (ret == -EINVAL) ? -E2BIG : ret;
	}
	if (path[0] == '\0') {
		ret = -EINVAL;
		goto out;
	}

	tp_event = create_local_trace_uprobe(path, p_event->attr.probe_offset,
					     ref_ctr_offset, is_retprobe);
	if (IS_ERR(tp_event)) {
		ret = PTR_ERR(tp_event);
		goto out;
	}

	/*
	mutex_lock(&event_mutex);
	ret = perf_trace_event_init(tp_event, p_event);
	if (ret)
		destroy_local_trace_uprobe(tp_event);
	mutex_unlock(&event_mutex);
out:
	kfree(path);
	return ret;
}

void perf_uprobe_destroy(struct perf_event *p_event)
{
	mutex_lock(&event_mutex);
	perf_trace_event_close(p_event);
	perf_trace_event_unreg(p_event);
	mutex_unlock(&event_mutex);
	destroy_local_trace_uprobe(p_event->tp_event);
}
#endif /* CONFIG_UPROBE_EVENTS */

int perf_trace_add(struct perf_event *p_event, int flags)
{
	struct trace_event_call *tp_event = p_event->tp_event;

	if (!(flags & PERF_EF_START))
		p_event->hw.state = PERF_HES_STOPPED;

	/*
	if (!tp_event->class->reg(tp_event, TRACE_REG_PERF_ADD, p_event)) {
		struct hlist_head __percpu *pcpu_list;
		struct hlist_head *list;

		pcpu_list = tp_event->perf_events;
		if (WARN_ON_ONCE(!pcpu_list))
			return -EINVAL;

		list = this_cpu_ptr(pcpu_list);
		hlist_add_head_rcu(&p_event->hlist_entry, list);
	}

	return 0;
}

void perf_trace_del(struct perf_event *p_event, int flags)
{
	struct trace_event_call *tp_event = p_event->tp_event;

	/*
	if (!tp_event->class->reg(tp_event, TRACE_REG_PERF_DEL, p_event))
		hlist_del_rcu(&p_event->hlist_entry);
}

void *perf_trace_buf_alloc(int size, struct pt_regs **regs, int *rctxp)
{
	char *raw_data;
	int rctx;

	BUILD_BUG_ON(PERF_MAX_TRACE_SIZE % sizeof(unsigned long));

	if (WARN_ONCE(size > PERF_MAX_TRACE_SIZE,
		      "perf buffer not large enough, wanted %d, have %d",
		      size, PERF_MAX_TRACE_SIZE))
		return NULL;

	if (rctx < 0)
		return NULL;

	if (regs)
		*regs = this_cpu_ptr(&__perf_regs[rctx]);
	raw_data = this_cpu_ptr(perf_trace_buf[rctx]);

	/* zero the dead bytes from align to not leak stack to user */
	memset(&raw_data[size - sizeof(u64)], 0, sizeof(u64));
	return raw_data;
}
EXPORT_SYMBOL_GPL(perf_trace_buf_alloc);
NOKPROBE_SYMBOL(perf_trace_buf_alloc);

void perf_trace_buf_update(void *record, u16 type)
{
	struct trace_entry *entry = record;

	tracing_generic_entry_update(entry, type, tracing_gen_ctx());
}
NOKPROBE_SYMBOL(perf_trace_buf_update);

#ifdef CONFIG_FUNCTION_TRACER
static void
perf_ftrace_function_call(unsigned long ip, unsigned long parent_ip,
			  struct ftrace_ops *ops,  struct ftrace_regs *fregs)
{
	struct ftrace_entry *entry;
	struct perf_event *event;
	struct hlist_head head;
	struct pt_regs regs;
	int rctx;
	int bit;

	if (!rcu_is_watching())
		return;

	bit = ftrace_test_recursion_trylock(ip, parent_ip);
	if (bit < 0)
		return;

	if ((unsigned long)ops->private != smp_processor_id())
		goto out;

	event = container_of(ops, struct perf_event, ftrace_ops);

	/*
	head.first = &event->hlist_entry;

#define ENTRY_SIZE (ALIGN(sizeof(struct ftrace_entry) + sizeof(u32), \
		    sizeof(u64)) - sizeof(u32))

	BUILD_BUG_ON(ENTRY_SIZE > PERF_MAX_TRACE_SIZE);

	memset(&regs, 0, sizeof(regs));
	perf_fetch_caller_regs(&regs);

	entry = perf_trace_buf_alloc(ENTRY_SIZE, NULL, &rctx);
	if (!entry)
		goto out;

	entry->ip = ip;
	entry->parent_ip = parent_ip;
	perf_trace_buf_submit(entry, ENTRY_SIZE, rctx, TRACE_FN,
			      1, &regs, &head, NULL);

out:
	ftrace_test_recursion_unlock(bit);
#undef ENTRY_SIZE
}

static int perf_ftrace_function_register(struct perf_event *event)
{
	struct ftrace_ops *ops = &event->ftrace_ops;

	ops->func    = perf_ftrace_function_call;
	ops->private = (void *)(unsigned long)nr_cpu_ids;

	return register_ftrace_function(ops);
}

static int perf_ftrace_function_unregister(struct perf_event *event)
{
	struct ftrace_ops *ops = &event->ftrace_ops;
	int ret = unregister_ftrace_function(ops);
	ftrace_free_filter(ops);
	return ret;
}

int perf_ftrace_event_register(struct trace_event_call *call,
			       enum trace_reg type, void *data)
{
	struct perf_event *event = data;

	switch (type) {
	case TRACE_REG_REGISTER:
	case TRACE_REG_UNREGISTER:
		break;
	case TRACE_REG_PERF_REGISTER:
	case TRACE_REG_PERF_UNREGISTER:
		return 0;
	case TRACE_REG_PERF_OPEN:
		return perf_ftrace_function_register(data);
	case TRACE_REG_PERF_CLOSE:
		return perf_ftrace_function_unregister(data);
	case TRACE_REG_PERF_ADD:
		event->ftrace_ops.private = (void *)(unsigned long)smp_processor_id();
		return 1;
	case TRACE_REG_PERF_DEL:
		event->ftrace_ops.private = (void *)(unsigned long)nr_cpu_ids;
		return 1;
	}

	return -EINVAL;
}
#endif /* CONFIG_FUNCTION_TRACER */
