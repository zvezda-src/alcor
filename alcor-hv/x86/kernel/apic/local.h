
#include <linux/jump_label.h>

#include <asm/irq_vectors.h>
#include <asm/apic.h>

void flat_init_apic_ldr(void);

int x2apic_apic_id_valid(u32 apicid);
int x2apic_apic_id_registered(void);
void __x2apic_send_IPI_dest(unsigned int apicid, int vector, unsigned int dest);
unsigned int x2apic_get_apic_id(unsigned long id);
u32 x2apic_set_apic_id(unsigned int id);
int x2apic_phys_pkg_id(int initial_apicid, int index_msb);
void x2apic_send_IPI_self(int vector);
void __x2apic_send_IPI_shorthand(int vector, u32 which);


DECLARE_STATIC_KEY_FALSE(apic_use_ipi_shorthand);

static inline unsigned int __prepare_ICR(unsigned int shortcut, int vector,
					 unsigned int dest)
{
	unsigned int icr = shortcut | dest;

	switch (vector) {
	default:
		icr |= APIC_DM_FIXED | vector;
		break;
	case NMI_VECTOR:
		icr |= APIC_DM_NMI;
		break;
	}
	return icr;
}

void __default_send_IPI_shortcut(unsigned int shortcut, int vector);

void __default_send_IPI_dest_field(unsigned int mask, int vector, unsigned int dest);

void default_send_IPI_single(int cpu, int vector);
void default_send_IPI_single_phys(int cpu, int vector);
void default_send_IPI_mask_sequence_phys(const struct cpumask *mask, int vector);
void default_send_IPI_mask_allbutself_phys(const struct cpumask *mask, int vector);
void default_send_IPI_allbutself(int vector);
void default_send_IPI_all(int vector);
void default_send_IPI_self(int vector);

#ifdef CONFIG_X86_32
void default_send_IPI_mask_sequence_logical(const struct cpumask *mask, int vector);
void default_send_IPI_mask_allbutself_logical(const struct cpumask *mask, int vector);
void default_send_IPI_mask_logical(const struct cpumask *mask, int vector);
#endif
