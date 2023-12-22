// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) International Business Machines Corp., 2001
 */

/*\
 * [Description]
 *
 * Testcase to test that getcwd(2) sets errno correctly.
 *
 * 1. getcwd(2) fails if buf points to a bad address.
 * 2. getcwd(2) fails if the size is invalid.
 * 3. getcwd(2) fails if the size is set to 0.
 * 4. getcwd(2) fails if the size is set to 1.
 * 5. getcwd(2) fails if buf points to NULL and the size is set to 1.
 *
 * Expected Result:
 *
 * linux syscall
 *
 * 1. getcwd(2) should return NULL and set errno to EFAULT.
 * 2. getcwd(2) should return NULL and set errno to EFAULT.
 * 3. getcwd(2) should return NULL and set errno to ERANGE.
 * 4. getcwd(2) should return NULL and set errno to ERANGE.
 * 5. getcwd(2) should return NULL and set errno to ERANGE.
 *
 * glibc and uclibc{,-ng}.
 *
 * 1. getcwd(2) should return NULL and set errno to EFAULT.
 * 2. getcwd(2) should return NULL and set errno to ENOMEM.
 * 3. getcwd(2) should return NULL and set errno to EINVAL.
 * 4. getcwd(2) should return NULL and set errno to ERANGE.
 * 5. getcwd(2) should return NULL and set errno to ERANGE.
 */

#include <errno.h>
#include <unistd.h>
#include <limits.h>
#include "tst_test.h"
#include "lapi/syscalls.h"

static char buffer[5];

static struct t_case {
	char *buf;
	size_t size;
	int exp_err;
	int exp_err_libc;
} tcases[] = {
	{(void *)-1, PATH_MAX, EFAULT, EFAULT},
	{NULL, (size_t)-1, EFAULT, ENOMEM},
	{buffer, 0, ERANGE, EINVAL},
	{buffer, 1, ERANGE, ERANGE},
	{NULL, 1, ERANGE, ERANGE},
};

static inline void check_getcwd(char *buf, size_t size, int exp_err)
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

static inline void tst_getcwd(char *buf, size_t size, int exp_err, int exp_err_libc)
{
	if (tst_variant == 0)
		TST_EXP_FAIL2(tst_syscall(__NR_getcwd, buf, size), exp_err);
	else
		check_getcwd(buf, size, exp_err_libc);
}

static void run(unsigned int n)
{
	struct t_case *tc = &tcases[n];

	/* https://github.com/linux-test-project/ltp/issues/1084 */
#if !defined(__GLIBC__) && !defined(__ANDROID__)
	if (tst_variant && !tc->buf) {
		tst_res(TCONF, "NULL buffer test skipped on MUSL due different implementation");
		return;
	}
#endif

	tst_getcwd(tc->buf, tc->size, tc->exp_err, tc->exp_err_libc);
}

static void setup(void)
{
	if (tst_variant == 0)
		tst_res(TINFO, "Testing getcwd with raw syscall");
	else
		tst_res(TINFO, "Testing getcwd with wrap syscall");
}

static struct tst_test test = {
	.setup = setup,
	.tcnt = ARRAY_SIZE(tcases),
	.test = run,
	.test_variants = 2,
};
