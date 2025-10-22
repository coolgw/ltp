// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2025 Wei Gao <wegao@suse.com>
 */

/*\
 * Test iocb RWF_* flags support: RWF_NOWAIT
 *
 * Checks if an asynchronous read operation with RWF_NOWAIT on a blocking
 * resource (empty pipe) fails immediately with -EAGAIN.
 */

#include "config.h"
#include "tst_test.h"
#include "lapi/syscalls.h"
#include "lapi/aio_abi.h"

static int fd[2];
static char buf[100];

static aio_context_t ctx;
static iocb cb;
static iocb *iocbs[] = {&cb};

static inline void io_prep_option(iocb *cb, int fd, void *buf,
			size_t count, long long offset, unsigned int opcode)
{
	memset(cb, 0, sizeof(*cb));
	cb->aio_fildes = fd;
	cb->aio_lio_opcode = opcode;
	cb->aio_buf = (uint64_t)buf;
	cb->aio_offset = offset;
	cb->aio_nbytes = count;
	cb->aio_rw_flags = RWF_NOWAIT;
}

static void setup(void)
{
	TST_EXP_PASS_SILENT(tst_syscall(__NR_io_setup, 1, &ctx));
	SAFE_PIPE(fd);
	io_prep_option(&cb, fd[0], buf, sizeof(buf), 0, IOCB_CMD_PREAD);
}

static void cleanup(void)
{
	if (fd[0])
		SAFE_CLOSE(fd[0]);

	if (fd[1])
		SAFE_CLOSE(fd[1]);

	if (tst_syscall(__NR_io_destroy, ctx))
		tst_brk(TBROK | TERRNO, "io_destroy() failed");
}

static void run(void)
{
	struct io_event evbuf;
	struct timespec timeout = { .tv_sec = 1 };
	long nr = 1;

	TEST(tst_syscall(__NR_io_submit, ctx, nr, iocbs));

	if (TST_RET == nr)
		tst_res(TPASS, "io_submit() pass");
	else
		tst_res(TFAIL | TTERRNO, "io_submit() returns %ld, expected %ld", TST_RET, nr);

	tst_syscall(__NR_io_getevents, ctx, 1, 1, &evbuf, &timeout);

	if (evbuf.res == -EAGAIN)
		tst_res(TINFO, "io_submit RWF_NOWAIT flag check pass");
	else
		tst_res(TFAIL | TTERRNO, "io_submit expect EAGAIN, but get %s", strerror(-evbuf.res));

}

static struct tst_test test = {
	.test_all = run,
	.needs_kconfigs = (const char *[]) {
		"CONFIG_AIO=y",
		NULL
	},
	.setup = setup,
	.cleanup = cleanup,
};
