
#include <linux/export.h>
#include <linux/kernel.h>
#include <linux/acpi.h>
#include <linux/cper.h>
#include <acpi/apei.h>
#include <acpi/ghes.h>
#include <asm/mce.h>

#include "internal.h"

void apei_mce_report_mem_error(int severity, struct cper_sec_mem_err *mem_err)
{
	struct mce m;

	if (!(mem_err->validation_bits & CPER_MEM_VALID_PA))
		return;

	mce_setup(&m);
	m.bank = -1;
	/* Fake a memory read error with unknown channel */
	m.status = MCI_STATUS_VAL | MCI_STATUS_EN | MCI_STATUS_ADDRV | MCI_STATUS_MISCV | 0x9f;
	m.misc = (MCI_MISC_ADDR_PHYS << 6) | PAGE_SHIFT;

	if (severity >= GHES_SEV_RECOVERABLE)
		m.status |= MCI_STATUS_UC;

	if (severity >= GHES_SEV_PANIC) {
		m.status |= MCI_STATUS_PCC;
		m.tsc = rdtsc();
	}

	m.addr = mem_err->physical_addr;
	mce_log(&m);
}
EXPORT_SYMBOL_GPL(apei_mce_report_mem_error);

int apei_smca_report_x86_error(struct cper_ia_proc_ctx *ctx_info, u64 lapic_id)
{
	const u64 *i_mce = ((const u64 *) (ctx_info + 1));
	unsigned int cpu;
	struct mce m;

	if (!boot_cpu_has(X86_FEATURE_SMCA))
		return -EINVAL;

	/*
	if ((ctx_info->msr_addr & MSR_AMD64_SMCA_MC0_STATUS) !=
				  MSR_AMD64_SMCA_MC0_STATUS)
		return -EINVAL;

	/*
	if (ctx_info->reg_arr_size < 48)
		return -EINVAL;

	mce_setup(&m);

	m.extcpu = -1;
	m.socketid = -1;

	for_each_possible_cpu(cpu) {
		if (cpu_data(cpu).initial_apicid == lapic_id) {
			m.extcpu = cpu;
			m.socketid = cpu_data(m.extcpu).phys_proc_id;
			break;
		}
	}

	m.apicid = lapic_id;
	m.bank = (ctx_info->msr_addr >> 4) & 0xFF;
	m.status = *i_mce;
	m.addr = *(i_mce + 1);
	m.misc = *(i_mce + 2);
	/* Skipping MCA_CONFIG */
	m.ipid = *(i_mce + 4);
	m.synd = *(i_mce + 5);

	mce_log(&m);

	return 0;
}

#define CPER_CREATOR_MCE						\
	GUID_INIT(0x75a574e3, 0x5052, 0x4b29, 0x8a, 0x8e, 0xbe, 0x2c,	\
		  0x64, 0x90, 0xb8, 0x9d)
#define CPER_SECTION_TYPE_MCE						\
	GUID_INIT(0xfe08ffbe, 0x95e4, 0x4be7, 0xbc, 0x73, 0x40, 0x96,	\
		  0x04, 0x4a, 0x38, 0xfc)

struct cper_mce_record {
	struct cper_record_header hdr;
	struct cper_section_descriptor sec_hdr;
	struct mce mce;
} __packed;

int apei_write_mce(struct mce *m)
{
	struct cper_mce_record rcd;

	memset(&rcd, 0, sizeof(rcd));
	memcpy(rcd.hdr.signature, CPER_SIG_RECORD, CPER_SIG_SIZE);
	rcd.hdr.revision = CPER_RECORD_REV;
	rcd.hdr.signature_end = CPER_SIG_END;
	rcd.hdr.section_count = 1;
	rcd.hdr.error_severity = CPER_SEV_FATAL;
	/* timestamp, platform_id, partition_id are all invalid */
	rcd.hdr.validation_bits = 0;
	rcd.hdr.record_length = sizeof(rcd);
	rcd.hdr.creator_id = CPER_CREATOR_MCE;
	rcd.hdr.notification_type = CPER_NOTIFY_MCE;
	rcd.hdr.record_id = cper_next_record_id();
	rcd.hdr.flags = CPER_HW_ERROR_FLAGS_PREVERR;

	rcd.sec_hdr.section_offset = (void *)&rcd.mce - (void *)&rcd;
	rcd.sec_hdr.section_length = sizeof(rcd.mce);
	rcd.sec_hdr.revision = CPER_SEC_REV;
	/* fru_id and fru_text is invalid */
	rcd.sec_hdr.validation_bits = 0;
	rcd.sec_hdr.flags = CPER_SEC_PRIMARY;
	rcd.sec_hdr.section_type = CPER_SECTION_TYPE_MCE;
	rcd.sec_hdr.section_severity = CPER_SEV_FATAL;

	memcpy(&rcd.mce, m, sizeof(*m));

	return erst_write(&rcd.hdr);
}

ssize_t apei_read_mce(struct mce *m, u64 *record_id)
{
	struct cper_mce_record rcd;
	int rc, pos;

	rc = erst_get_record_id_begin(&pos);
	if (rc)
		return rc;
retry:
	rc = erst_get_record_id_next(&pos, record_id);
	if (rc)
		goto out;
	/* no more record */
	if (*record_id == APEI_ERST_INVALID_RECORD_ID)
		goto out;
	rc = erst_read_record(*record_id, &rcd.hdr, sizeof(rcd), sizeof(rcd),
			&CPER_CREATOR_MCE);
	/* someone else has cleared the record, try next one */
	if (rc == -ENOENT)
		goto retry;
	else if (rc < 0)
		goto out;

	memcpy(m, &rcd.mce, sizeof(*m));
	rc = sizeof(*m);
out:
	erst_get_record_id_end();

	return rc;
}

int apei_check_mce(void)
{
	return erst_get_record_count();
}

int apei_clear_mce(u64 record_id)
{
	return erst_clear(record_id);
}
