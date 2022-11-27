
#ifndef __UM_ARCHPARAM_H
#define __UM_ARCHPARAM_H

#ifdef CONFIG_X86_32

#ifdef CONFIG_X86_PAE
#define LAST_PKMAP 512
#else
#define LAST_PKMAP 1024
#endif

#endif

#endif
