#ifndef __TRACING_MAP_H
#define __TRACING_MAP_H

#define TRACING_MAP_BITS_DEFAULT	11
#define TRACING_MAP_BITS_MAX		17
#define TRACING_MAP_BITS_MIN		7

#define TRACING_MAP_KEYS_MAX		3
#define TRACING_MAP_VALS_MAX		3
#define TRACING_MAP_FIELDS_MAX		(TRACING_MAP_KEYS_MAX + \
					 TRACING_MAP_VALS_MAX)
#define TRACING_MAP_VARS_MAX		16
#define TRACING_MAP_SORT_KEYS_MAX	2

typedef int (*tracing_map_cmp_fn_t) (void *val_a, void *val_b);


struct tracing_map_field {
	tracing_map_cmp_fn_t		cmp_fn;
	union {
		atomic64_t			sum;
		unsigned int			offset;
	};
};

struct tracing_map_elt {
	struct tracing_map		*map;
	struct tracing_map_field	*fields;
	atomic64_t			*vars;
	bool				*var_set;
	void				*key;
	void				*private_data;
};

struct tracing_map_entry {
	u32				key;
	struct tracing_map_elt		*val;
};

struct tracing_map_sort_key {
	unsigned int			field_idx;
	bool				descending;
};

struct tracing_map_sort_entry {
	void				*key;
	struct tracing_map_elt		*elt;
	bool				elt_copied;
	bool				dup;
};

struct tracing_map_array {
	unsigned int entries_per_page;
	unsigned int entry_size_shift;
	unsigned int entry_shift;
	unsigned int entry_mask;
	unsigned int n_pages;
	void **pages;
};

#define TRACING_MAP_ARRAY_ELT(array, idx)				\
	(array->pages[idx >> array->entry_shift] +			\
	 ((idx & array->entry_mask) << array->entry_size_shift))

#define TRACING_MAP_ENTRY(array, idx)					\
	((struct tracing_map_entry *)TRACING_MAP_ARRAY_ELT(array, idx))

#define TRACING_MAP_ELT(array, idx)					\
	((struct tracing_map_elt **)TRACING_MAP_ARRAY_ELT(array, idx))

struct tracing_map {
	unsigned int			key_size;
	unsigned int			map_bits;
	unsigned int			map_size;
	unsigned int			max_elts;
	atomic_t			next_elt;
	struct tracing_map_array	*elts;
	struct tracing_map_array	*map;
	const struct tracing_map_ops	*ops;
	void				*private_data;
	struct tracing_map_field	fields[TRACING_MAP_FIELDS_MAX];
	unsigned int			n_fields;
	int				key_idx[TRACING_MAP_KEYS_MAX];
	unsigned int			n_keys;
	struct tracing_map_sort_key	sort_key;
	unsigned int			n_vars;
	atomic64_t			hits;
	atomic64_t			drops;
};

struct tracing_map_ops {
	int			(*elt_alloc)(struct tracing_map_elt *elt);
	void			(*elt_free)(struct tracing_map_elt *elt);
	void			(*elt_clear)(struct tracing_map_elt *elt);
	void			(*elt_init)(struct tracing_map_elt *elt);
};

extern struct tracing_map *
tracing_map_create(unsigned int map_bits,
		   unsigned int key_size,
		   const struct tracing_map_ops *ops,
		   void *private_data);
extern int tracing_map_init(struct tracing_map *map);

extern int tracing_map_add_sum_field(struct tracing_map *map);
extern int tracing_map_add_var(struct tracing_map *map);
extern int tracing_map_add_key_field(struct tracing_map *map,
				     unsigned int offset,
				     tracing_map_cmp_fn_t cmp_fn);

extern void tracing_map_destroy(struct tracing_map *map);
extern void tracing_map_clear(struct tracing_map *map);

extern struct tracing_map_elt *
tracing_map_insert(struct tracing_map *map, void *key);
extern struct tracing_map_elt *
tracing_map_lookup(struct tracing_map *map, void *key);

extern tracing_map_cmp_fn_t tracing_map_cmp_num(int field_size,
						int field_is_signed);
extern int tracing_map_cmp_string(void *val_a, void *val_b);
extern int tracing_map_cmp_none(void *val_a, void *val_b);

extern void tracing_map_update_sum(struct tracing_map_elt *elt,
				   unsigned int i, u64 n);
extern void tracing_map_set_var(struct tracing_map_elt *elt,
				unsigned int i, u64 n);
extern bool tracing_map_var_set(struct tracing_map_elt *elt, unsigned int i);
extern u64 tracing_map_read_sum(struct tracing_map_elt *elt, unsigned int i);
extern u64 tracing_map_read_var(struct tracing_map_elt *elt, unsigned int i);
extern u64 tracing_map_read_var_once(struct tracing_map_elt *elt, unsigned int i);

extern void tracing_map_set_field_descr(struct tracing_map *map,
					unsigned int i,
					unsigned int key_offset,
					tracing_map_cmp_fn_t cmp_fn);
extern int
tracing_map_sort_entries(struct tracing_map *map,
			 struct tracing_map_sort_key *sort_keys,
			 unsigned int n_sort_keys,
			 struct tracing_map_sort_entry ***sort_entries);

extern void
tracing_map_destroy_sort_entries(struct tracing_map_sort_entry **entries,
				 unsigned int n_entries);
#endif /* __TRACING_MAP_H */
