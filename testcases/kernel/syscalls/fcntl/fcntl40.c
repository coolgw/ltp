// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2024 SUSE Wei Gao <wegao@suse.com>
 */

/*\
 * Basic test for fcntl using F_CREATED_QUERY.
 *
 * It is based on the following kernel commit:
 * commit d0fe8920cbe42547798fd806f078eeaaba05df18
 * Author: Christian Brauner brauner@kernel.org
 * Date: Wed Jul 24 15:15:36 2024 +0200
 */

#include "lapi/fcntl.h"
#include "tst_test.h"

static void verify_fcntl(void)
{
	for (int i = 0; i < 101; i++) {
		int fd;
		char path[PATH_MAX];

		fd = SAFE_OPEN("/dev/null", O_RDONLY | O_CLOEXEC);

		/* We didn't create "/dev/null". */
		TST_EXP_EQ_LI(fcntl(fd, F_CREATED_QUERY, 0), 0);
		close(fd);

		sprintf(path, "aaaa_%d", i);
		fd = SAFE_OPEN(path, O_CREAT | O_RDONLY | O_CLOEXEC, 0600);

		/* We created "aaaa_%d". */
		TST_EXP_EQ_LI(fcntl(fd, F_CREATED_QUERY, 0), 1);
		close(fd);

		fd = SAFE_OPEN(path, O_RDONLY | O_CLOEXEC);

		/* We're opening it again, so no positive creation check. */
		TST_EXP_EQ_LI(fcntl(fd, F_CREATED_QUERY, 0), 0);
		close(fd);
		unlink(path);
	}
}

static struct tst_test test = {
	.test_all = verify_fcntl,
	.needs_tmpdir = 1,
	.min_kver = "6.12",
};
