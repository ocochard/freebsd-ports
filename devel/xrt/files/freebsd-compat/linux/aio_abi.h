/*
 * FreeBSD: types of the Linux native AIO ABI, used only by the Alveo
 * QDMA path of libxrt_core.  The io_* calls fail with ENOSYS.
 */
#ifndef _FREEBSD_COMPAT_LINUX_AIO_ABI_H_
#define	_FREEBSD_COMPAT_LINUX_AIO_ABI_H_

#include <stdint.h>

typedef unsigned long aio_context_t;

enum {
	IOCB_CMD_PREAD = 0,
	IOCB_CMD_PWRITE = 1,
	IOCB_CMD_FSYNC = 2,
	IOCB_CMD_FDSYNC = 3,
	IOCB_CMD_NOOP = 6,
	IOCB_CMD_PREADV = 7,
	IOCB_CMD_PWRITEV = 8,
};

struct io_event {
	uint64_t	data;
	uint64_t	obj;
	int64_t		res;
	int64_t		res2;
};

struct iocb {
	uint64_t	aio_data;
	uint32_t	aio_key;
	int32_t		aio_rw_flags;
	uint16_t	aio_lio_opcode;
	int16_t		aio_reqprio;
	uint32_t	aio_fildes;
	uint64_t	aio_buf;
	uint64_t	aio_nbytes;
	int64_t		aio_offset;
	uint64_t	aio_reserved2;
	uint32_t	aio_flags;
	uint32_t	aio_resfd;
};

#endif
