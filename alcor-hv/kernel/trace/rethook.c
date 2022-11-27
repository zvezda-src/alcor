
#define pr_fmt(fmt) "rethook: " fmt

#include <linux/bug.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/preempt.h>
#include <linux/rethook.h>
#include <linux/slab.h>
#include <linux/sort.h>


void rethook_flush_task(struct task_struct *tk)
{
	struct rethook_node *rhn;
	struct llist_node *node;

	node = __llist_del_all(&tk->rethooks);
	while (node) {
		rhn = container_of(node, struct rethook_node, llist);
		node = node->next;
		preempt_disable();
		rethook_recycle(rhn);
		preempt_enable();
	}
}

static void rethook_free_rcu(struct rcu_head *head)
{
	struct rethook *rh = container_of(head, struct rethook, rcu);
	struct rethook_node *rhn;
	struct freelist_node *node;
	int count = 1;

	node = rh->pool.head;
	while (node) {
		rhn = container_of(node, struct rethook_node, freelist);
		node = node->next;
		kfree(rhn);
		count++;
	}

	/* The rh->ref is the number of pooled node + 1 */
	if (refcount_sub_and_test(count, &rh->ref))
		kfree(rh);
}

void rethook_free(struct rethook *rh)
{
	WRITE_ONCE(rh->handler, NULL);

	call_rcu(&rh->rcu, rethook_free_rcu);
}

struct rethook *rethook_alloc(void *data, rethook_handler_t handler)
{
	struct rethook *rh = kzalloc(sizeof(struct rethook), GFP_KERNEL);

	if (!rh || !handler)
		return NULL;

	rh->data = data;
	rh->handler = handler;
	rh->pool.head = NULL;
	refcount_set(&rh->ref, 1);

	return rh;
}

void rethook_add_node(struct rethook *rh, struct rethook_node *node)
{
	node->rethook = rh;
	freelist_add(&node->freelist, &rh->pool);
	refcount_inc(&rh->ref);
}

static void free_rethook_node_rcu(struct rcu_head *head)
{
	struct rethook_node *node = container_of(head, struct rethook_node, rcu);

	if (refcount_dec_and_test(&node->rethook->ref))
		kfree(node->rethook);
	kfree(node);
}

void rethook_recycle(struct rethook_node *node)
{
	lockdep_assert_preemption_disabled();

	if (likely(READ_ONCE(node->rethook->handler)))
		freelist_add(&node->freelist, &node->rethook->pool);
	else
		call_rcu(&node->rcu, free_rethook_node_rcu);
}
NOKPROBE_SYMBOL(rethook_recycle);

struct rethook_node *rethook_try_get(struct rethook *rh)
{
	rethook_handler_t handler = READ_ONCE(rh->handler);
	struct freelist_node *fn;

	lockdep_assert_preemption_disabled();

	/* Check whether @rh is going to be freed. */
	if (unlikely(!handler))
		return NULL;

	/*
	if (unlikely(!rcu_is_watching()))
		return NULL;

	fn = freelist_try_get(&rh->pool);
	if (!fn)
		return NULL;

	return container_of(fn, struct rethook_node, freelist);
}
NOKPROBE_SYMBOL(rethook_try_get);

void rethook_hook(struct rethook_node *node, struct pt_regs *regs, bool mcount)
{
	arch_rethook_prepare(node, regs, mcount);
	__llist_add(&node->llist, &current->rethooks);
}
NOKPROBE_SYMBOL(rethook_hook);

static unsigned long __rethook_find_ret_addr(struct task_struct *tsk,
					     struct llist_node **cur)
{
	struct rethook_node *rh = NULL;
	struct llist_node *node = *cur;

	if (!node)
		node = tsk->rethooks.first;
	else
		node = node->next;

	while (node) {
		rh = container_of(node, struct rethook_node, llist);
		if (rh->ret_addr != (unsigned long)arch_rethook_trampoline) {
			*cur = node;
			return rh->ret_addr;
		}
		node = node->next;
	}
	return 0;
}
NOKPROBE_SYMBOL(__rethook_find_ret_addr);

unsigned long rethook_find_ret_addr(struct task_struct *tsk, unsigned long frame,
				    struct llist_node **cur)
{
	struct rethook_node *rhn = NULL;
	unsigned long ret;

	if (WARN_ON_ONCE(!cur))
		return 0;

	if (WARN_ON_ONCE(tsk != current && task_is_running(tsk)))
		return 0;

	do {
		ret = __rethook_find_ret_addr(tsk, cur);
		if (!ret)
			break;
		rhn = container_of(*cur, struct rethook_node, llist);
	} while (rhn->frame != frame);

	return ret;
}
NOKPROBE_SYMBOL(rethook_find_ret_addr);

void __weak arch_rethook_fixup_return(struct pt_regs *regs,
				      unsigned long correct_ret_addr)
{
	/*
}

unsigned long rethook_trampoline_handler(struct pt_regs *regs,
					 unsigned long frame)
{
	struct llist_node *first, *node = NULL;
	unsigned long correct_ret_addr;
	rethook_handler_t handler;
	struct rethook_node *rhn;

	correct_ret_addr = __rethook_find_ret_addr(current, &node);
	if (!correct_ret_addr) {
		pr_err("rethook: Return address not found! Maybe there is a bug in the kernel\n");
		BUG_ON(1);
	}

	instruction_pointer_set(regs, correct_ret_addr);

	/*
	preempt_disable();

	/*
	first = current->rethooks.first;
	while (first) {
		rhn = container_of(first, struct rethook_node, llist);
		if (WARN_ON_ONCE(rhn->frame != frame))
			break;
		handler = READ_ONCE(rhn->rethook->handler);
		if (handler)
			handler(rhn, rhn->rethook->data, regs);

		if (first == node)
			break;
		first = first->next;
	}

	/* Fixup registers for returning to correct address. */
	arch_rethook_fixup_return(regs, correct_ret_addr);

	/* Unlink used shadow stack */
	first = current->rethooks.first;
	current->rethooks.first = node->next;
	node->next = NULL;

	while (first) {
		rhn = container_of(first, struct rethook_node, llist);
		first = first->next;
		rethook_recycle(rhn);
	}
	preempt_enable();

	return correct_ret_addr;
}
NOKPROBE_SYMBOL(rethook_trampoline_handler);
