
#ifndef __FAULTINFO_I386_H
#define __FAULTINFO_I386_H

struct faultinfo {
        int error_code; /* in ptrace_faultinfo misleadingly called is_write */
        unsigned long cr2; /* in ptrace_faultinfo called addr */
        int trap_no; /* missing in ptrace_faultinfo */
};

#define FAULT_WRITE(fi) ((fi).error_code & 2)
#define FAULT_ADDRESS(fi) ((fi).cr2)

#define SEGV_IS_FIXABLE(fi)	((fi)->trap_no == 14)

#define PTRACE_FULL_FAULTINFO 0

#endif
