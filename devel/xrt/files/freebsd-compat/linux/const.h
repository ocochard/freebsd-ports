/* FreeBSD: bit and constant helpers of the Linux UAPI <linux/const.h>. */
#ifndef _FREEBSD_COMPAT_LINUX_CONST_H_
#define	_FREEBSD_COMPAT_LINUX_CONST_H_
#define	__AC(X, Y)	(X##Y)
#define	_AC(X, Y)	__AC(X, Y)
#define	_UL(x)		(_AC(x, UL))
#define	_ULL(x)		(_AC(x, ULL))
#define	_BITUL(x)	(_UL(1) << (x))
#define	_BITULL(x)	(_ULL(1) << (x))
#endif
