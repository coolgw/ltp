// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) International Business Machines Corp., 2001
 * Copyright (c) 2023 Wei Gao <wegao@suse.com>
 */

/*
 * DESCRIPTION
 * Testcase to test that getcwd() sets errno correctly.
 */

#include <errno.h>
#include <unistd.h>
#include <limits.h>
#include "tst_test.h"
#include "lapi/syscalls.h"

static char buffer[5];
struct getcwd_variants {
	void (*getcwd)(char *buf, size_t size, int exp_err);
	char *buf;
	size_t size;
	int exp_err;
};

static void verify_getcwd_raw_syscall(char *buf, size_t size, int exp_err);
static void verify_getcwd(char *buf, size_t size, int exp_err);

static struct getcwd_variants variants[] = {
#ifdef __GLIBC__
	{ .getcwd = verify_getcwd, .buf = NULL, .size = (size_t)-1, .exp_err = ENOMEM},
	{ .getcwd = verify_getcwd, .buf = NULL, .size = 1, .exp_err = ERANGE},
#endif
	{ .getcwd = verify_getcwd, .buf = (void *)-1, .size = PATH_MAX, .exp_err = EFAULT},
	{ .getcwd = verify_getcwd, .buf = buffer, .size = 0, .exp_err = EINVAL},
	{ .getcwd = verify_getcwd, .buf = buffer, .size = 1, .exp_err = ERANGE},
	{ .getcwd = verify_getcwd_raw_syscall, .buf = buffer, .size = 0, .exp_err = ERANGE},
	{ .getcwd = verify_getcwd_raw_syscall, .buf = (void *)-1, .size = PATH_MAX, .exp_err = EFAULT},
	{ .getcwd = verify_getcwd_raw_syscall, .buf = NULL, .size = (size_t)-1, .exp_err = EFAULT},
	{ .getcwd = verify_getcwd_raw_syscall, .buf = buffer, .size = 0, .exp_err = ERANGE},
	{ .getcwd = verify_getcwd_raw_syscall, .buf = buffer, .size = 1, .exp_err = ERANGE},
	{ .getcwd = verify_getcwd_raw_syscall, .buf = NULL, .size = 1, .exp_err = ERANGE},
};

static void verify_getcwd(char *buf, size_t size, int exp_err)
{
	char *res;

	errno = 0;
	res = getcwd(buf, size);
	TST_ERR = errno;
	if (res) {
		tst_res(TFAIL, "getcwd() succeeded unexpectedly");
		return;
	}

	if (TST_ERR != exp_err) {
		tst_res(TFAIL | TTERRNO, "getcwd() failed unexpectedly, expected %s",
				tst_strerrno(exp_err));
		return;
	}

	tst_res(TPASS | TTERRNO, "getcwd() failed as expected");

}

static void verify_getcwd_raw_syscall(char *buf, size_t size, int exp_err)
{

	TST_EXP_FAIL2(tst_syscall(__NR_getcwd, buf, size), exp_err);
}

static void verify(void)
{
	struct getcwd_variants *tv = &variants[tst_variant];

	tv->getcwd(tv->buf, tv->size, tv->exp_err);
}

static struct tst_test test = {
	.test_variants = ARRAY_SIZE(variants),
	.test_all = verify,
};
