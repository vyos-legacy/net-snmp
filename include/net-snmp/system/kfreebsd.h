#include "freebsd6.h"
#define freebsd6 freebsd6

#include <osreldate.h>
#if defined(__FreeBSD_kernel_version) && !defined(__FreeBSD_version)
#define __FreeBSD_version __FreeBSD_kernel_version
#endif

#include <sys/queue.h>
#include <sys/_types.h>

