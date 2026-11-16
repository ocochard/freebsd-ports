/*
 * FreeBSD: superpages are transparent, there is no MAP_HUGETLB.  Used
 * only by the Alveo CMA path of libxrt_core.
 */
#ifndef _FREEBSD_COMPAT_ASM_MMAN_H_
#define	_FREEBSD_COMPAT_ASM_MMAN_H_
#include <sys/mman.h>
#ifndef MAP_HUGETLB
#define	MAP_HUGETLB	0
#endif
#ifndef MAP_HUGE_SHIFT
#define	MAP_HUGE_SHIFT	26
#endif
#endif
