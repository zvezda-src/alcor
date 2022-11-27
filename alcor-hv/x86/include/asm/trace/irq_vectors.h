#undef TRACE_SYSTEM
#define TRACE_SYSTEM irq_vectors

#if !defined(_TRACE_IRQ_VECTORS_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_IRQ_VECTORS_H

#include <linux/tracepoint.h>
#include <asm/trace/common.h>

#ifdef CONFIG_X86_LOCAL_APIC

DECLARE_EVENT_CLASS(x86_irq_vector,

	TP_PROTO(int vector),

	TP_ARGS(vector),

	TP_STRUCT__entry(
		__field(		int,	vector	)
	),

	TP_fast_assign(
		__entry->vector = vector;
	),

	TP_printk("vector=%d", __entry->vector) );

#define DEFINE_IRQ_VECTOR_EVENT(name)		\
DEFINE_EVENT_FN(x86_irq_vector, name##_entry,	\
	TP_PROTO(int vector),			\
	TP_ARGS(vector), NULL, NULL);		\
DEFINE_EVENT_FN(x86_irq_vector, name##_exit,	\
	TP_PROTO(int vector),			\
	TP_ARGS(vector), NULL, NULL);

DEFINE_IRQ_VECTOR_EVENT(local_timer);

DEFINE_IRQ_VECTOR_EVENT(spurious_apic);

DEFINE_IRQ_VECTOR_EVENT(error_apic);

DEFINE_IRQ_VECTOR_EVENT(x86_platform_ipi);

#ifdef CONFIG_IRQ_WORK
DEFINE_IRQ_VECTOR_EVENT(irq_work);

TRACE_EVENT_PERF_PERM(irq_work_exit, is_sampling_event(p_event) ? -EPERM : 0);
#endif

#ifdef CONFIG_SMP
DEFINE_IRQ_VECTOR_EVENT(reschedule);

DEFINE_IRQ_VECTOR_EVENT(call_function);

DEFINE_IRQ_VECTOR_EVENT(call_function_single);
#endif

#ifdef CONFIG_X86_MCE_THRESHOLD
DEFINE_IRQ_VECTOR_EVENT(threshold_apic);
#endif

#ifdef CONFIG_X86_MCE_AMD
DEFINE_IRQ_VECTOR_EVENT(deferred_error_apic);
#endif

#ifdef CONFIG_X86_THERMAL_VECTOR
DEFINE_IRQ_VECTOR_EVENT(thermal_apic);
#endif

TRACE_EVENT(vector_config,

	TP_PROTO(unsigned int irq, unsigned int vector,
		 unsigned int cpu, unsigned int apicdest),

	TP_ARGS(irq, vector, cpu, apicdest),

	TP_STRUCT__entry(
		__field(	unsigned int,	irq		)
		__field(	unsigned int,	vector		)
		__field(	unsigned int,	cpu		)
		__field(	unsigned int,	apicdest	)
	),

	TP_fast_assign(
		__entry->irq		= irq;
		__entry->vector		= vector;
		__entry->cpu		= cpu;
		__entry->apicdest	= apicdest;
	),

	TP_printk("irq=%u vector=%u cpu=%u apicdest=0x%08x",
		  __entry->irq, __entry->vector, __entry->cpu,
		  __entry->apicdest)
);

DECLARE_EVENT_CLASS(vector_mod,

	TP_PROTO(unsigned int irq, unsigned int vector,
		 unsigned int cpu, unsigned int prev_vector,
		 unsigned int prev_cpu),

	TP_ARGS(irq, vector, cpu, prev_vector, prev_cpu),

	TP_STRUCT__entry(
		__field(	unsigned int,	irq		)
		__field(	unsigned int,	vector		)
		__field(	unsigned int,	cpu		)
		__field(	unsigned int,	prev_vector	)
		__field(	unsigned int,	prev_cpu	)
	),

	TP_fast_assign(
		__entry->irq		= irq;
		__entry->vector		= vector;
		__entry->cpu		= cpu;
		__entry->prev_vector	= prev_vector;
		__entry->prev_cpu	= prev_cpu;

	),

	TP_printk("irq=%u vector=%u cpu=%u prev_vector=%u prev_cpu=%u",
		  __entry->irq, __entry->vector, __entry->cpu,
		  __entry->prev_vector, __entry->prev_cpu)
);

#define DEFINE_IRQ_VECTOR_MOD_EVENT(name)				\
DEFINE_EVENT_FN(vector_mod, name,					\
	TP_PROTO(unsigned int irq, unsigned int vector,			\
		 unsigned int cpu, unsigned int prev_vector,		\
		 unsigned int prev_cpu),				\
	TP_ARGS(irq, vector, cpu, prev_vector, prev_cpu), NULL, NULL);	\

DEFINE_IRQ_VECTOR_MOD_EVENT(vector_update);
DEFINE_IRQ_VECTOR_MOD_EVENT(vector_clear);

DECLARE_EVENT_CLASS(vector_reserve,

	TP_PROTO(unsigned int irq, int ret),

	TP_ARGS(irq, ret),

	TP_STRUCT__entry(
		__field(	unsigned int,	irq	)
		__field(	int,		ret	)
	),

	TP_fast_assign(
		__entry->irq = irq;
		__entry->ret = ret;
	),

	TP_printk("irq=%u ret=%d", __entry->irq, __entry->ret)
);

#define DEFINE_IRQ_VECTOR_RESERVE_EVENT(name)	\
DEFINE_EVENT_FN(vector_reserve, name,	\
	TP_PROTO(unsigned int irq, int ret),	\
	TP_ARGS(irq, ret), NULL, NULL);		\

DEFINE_IRQ_VECTOR_RESERVE_EVENT(vector_reserve_managed);
DEFINE_IRQ_VECTOR_RESERVE_EVENT(vector_reserve);

TRACE_EVENT(vector_alloc,

	TP_PROTO(unsigned int irq, unsigned int vector, bool reserved,
		 int ret),

	TP_ARGS(irq, vector, reserved, ret),

	TP_STRUCT__entry(
		__field(	unsigned int,	irq		)
		__field(	unsigned int,	vector		)
		__field(	bool,		reserved	)
		__field(	int,		ret		)
	),

	TP_fast_assign(
		__entry->irq		= irq;
		__entry->vector		= ret < 0 ? 0 : vector;
		__entry->reserved	= reserved;
		__entry->ret		= ret > 0 ? 0 : ret;
	),

	TP_printk("irq=%u vector=%u reserved=%d ret=%d",
		  __entry->irq, __entry->vector,
		  __entry->reserved, __entry->ret)
);

TRACE_EVENT(vector_alloc_managed,

	TP_PROTO(unsigned int irq, unsigned int vector,
		 int ret),

	TP_ARGS(irq, vector, ret),

	TP_STRUCT__entry(
		__field(	unsigned int,	irq		)
		__field(	unsigned int,	vector		)
		__field(	int,		ret		)
	),

	TP_fast_assign(
		__entry->irq		= irq;
		__entry->vector		= ret < 0 ? 0 : vector;
		__entry->ret		= ret > 0 ? 0 : ret;
	),

	TP_printk("irq=%u vector=%u ret=%d",
		  __entry->irq, __entry->vector, __entry->ret)
);

DECLARE_EVENT_CLASS(vector_activate,

	TP_PROTO(unsigned int irq, bool is_managed, bool can_reserve,
		 bool reserve),

	TP_ARGS(irq, is_managed, can_reserve, reserve),

	TP_STRUCT__entry(
		__field(	unsigned int,	irq		)
		__field(	bool,		is_managed	)
		__field(	bool,		can_reserve	)
		__field(	bool,		reserve		)
	),

	TP_fast_assign(
		__entry->irq		= irq;
		__entry->is_managed	= is_managed;
		__entry->can_reserve	= can_reserve;
		__entry->reserve	= reserve;
	),

	TP_printk("irq=%u is_managed=%d can_reserve=%d reserve=%d",
		  __entry->irq, __entry->is_managed, __entry->can_reserve,
		  __entry->reserve)
);

#define DEFINE_IRQ_VECTOR_ACTIVATE_EVENT(name)				\
DEFINE_EVENT_FN(vector_activate, name,					\
	TP_PROTO(unsigned int irq, bool is_managed,			\
		 bool can_reserve, bool reserve),			\
	TP_ARGS(irq, is_managed, can_reserve, reserve), NULL, NULL);	\

DEFINE_IRQ_VECTOR_ACTIVATE_EVENT(vector_activate);
DEFINE_IRQ_VECTOR_ACTIVATE_EVENT(vector_deactivate);

TRACE_EVENT(vector_teardown,

	TP_PROTO(unsigned int irq, bool is_managed, bool has_reserved),

	TP_ARGS(irq, is_managed, has_reserved),

	TP_STRUCT__entry(
		__field(	unsigned int,	irq		)
		__field(	bool,		is_managed	)
		__field(	bool,		has_reserved	)
	),

	TP_fast_assign(
		__entry->irq		= irq;
		__entry->is_managed	= is_managed;
		__entry->has_reserved	= has_reserved;
	),

	TP_printk("irq=%u is_managed=%d has_reserved=%d",
		  __entry->irq, __entry->is_managed, __entry->has_reserved)
);

TRACE_EVENT(vector_setup,

	TP_PROTO(unsigned int irq, bool is_legacy, int ret),

	TP_ARGS(irq, is_legacy, ret),

	TP_STRUCT__entry(
		__field(	unsigned int,	irq		)
		__field(	bool,		is_legacy	)
		__field(	int,		ret		)
	),

	TP_fast_assign(
		__entry->irq		= irq;
		__entry->is_legacy	= is_legacy;
		__entry->ret		= ret;
	),

	TP_printk("irq=%u is_legacy=%d ret=%d",
		  __entry->irq, __entry->is_legacy, __entry->ret)
);

TRACE_EVENT(vector_free_moved,

	TP_PROTO(unsigned int irq, unsigned int cpu, unsigned int vector,
		 bool is_managed),

	TP_ARGS(irq, cpu, vector, is_managed),

	TP_STRUCT__entry(
		__field(	unsigned int,	irq		)
		__field(	unsigned int,	cpu		)
		__field(	unsigned int,	vector		)
		__field(	bool,		is_managed	)
	),

	TP_fast_assign(
		__entry->irq		= irq;
		__entry->cpu		= cpu;
		__entry->vector		= vector;
		__entry->is_managed	= is_managed;
	),

	TP_printk("irq=%u cpu=%u vector=%u is_managed=%d",
		  __entry->irq, __entry->cpu, __entry->vector,
		  __entry->is_managed)
);


#endif /* CONFIG_X86_LOCAL_APIC */

#undef TRACE_INCLUDE_PATH
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_PATH .
#define TRACE_INCLUDE_FILE irq_vectors
#endif /*  _TRACE_IRQ_VECTORS_H */

#include <trace/define_trace.h>
