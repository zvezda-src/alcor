
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/livepatch.h>
#include "core.h"
#include "state.h"
#include "transition.h"

#define klp_for_each_state(patch, state)		\
	for (state = patch->states; state && state->id; state++)

struct klp_state *klp_get_state(struct klp_patch *patch, unsigned long id)
{
	struct klp_state *state;

	klp_for_each_state(patch, state) {
		if (state->id == id)
			return state;
	}

	return NULL;
}
EXPORT_SYMBOL_GPL(klp_get_state);

struct klp_state *klp_get_prev_state(unsigned long id)
{
	struct klp_patch *patch;
	struct klp_state *state, *last_state = NULL;

	if (WARN_ON_ONCE(!klp_transition_patch))
		return NULL;

	klp_for_each_patch(patch) {
		if (patch == klp_transition_patch)
			goto out;

		state = klp_get_state(patch, id);
		if (state)
			last_state = state;
	}

out:
	return last_state;
}
EXPORT_SYMBOL_GPL(klp_get_prev_state);

static bool klp_is_state_compatible(struct klp_patch *patch,
				    struct klp_state *old_state)
{
	struct klp_state *state;

	state = klp_get_state(patch, old_state->id);

	/* A cumulative livepatch must handle all already modified states. */
	if (!state)
		return !patch->replace;

	return state->version >= old_state->version;
}

bool klp_is_patch_compatible(struct klp_patch *patch)
{
	struct klp_patch *old_patch;
	struct klp_state *old_state;

	klp_for_each_patch(old_patch) {
		klp_for_each_state(old_patch, old_state) {
			if (!klp_is_state_compatible(patch, old_state))
				return false;
		}
	}

	return true;
}
