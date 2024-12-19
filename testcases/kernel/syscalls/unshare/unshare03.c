// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2024 Al Viro <viro@zeniv.linux.org.uk>
 * Copyright (C) 2024 Wei Gao <wegao@suse.com>
 */

/*\
 * [Description]
 *
 * Test case is adapted from the kernel self test unshare_test.c.
 * Test coverage for dup_fd() failure handling in unshare_fd()
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/syscall.h>
#include <sched.h>
#include <limits.h>
#include <unistd.h>

#include "tst_test.h"
#include "config.h"
#include "lapi/sched.h"

#define FS_NR_OPEN "/proc/sys/fs/nr_open"

#ifdef HAVE_UNSHARE

static void run(void)
{
	int nr_open;
	struct rlimit rlimit;
	pid_t pid;
	struct clone_args args = {
		.flags = CLONE_FILES,
		.exit_signal = SIGCHLD,
	};

	SAFE_FILE_SCANF(FS_NR_OPEN, "%d", &nr_open);

	SAFE_FILE_PRINTF(FS_NR_OPEN, "%d", nr_open + 1024);

	SAFE_GETRLIMIT(RLIMIT_NOFILE, &rlimit);

	rlimit.rlim_cur = nr_open + 1024;
	rlimit.rlim_max = nr_open + 1024;

	SAFE_SETRLIMIT(RLIMIT_NOFILE, &rlimit);

	SAFE_DUP2(2, nr_open + 64);

	pid = clone3(&args, sizeof(args));

	if (pid < 0) {
		tst_res(TFAIL | TTERRNO, "clone3() failed");
		return;
	}

	if (!pid) {
		SAFE_FILE_PRINTF(FS_NR_OPEN, "%d", nr_open);
		TST_EXP_FAIL(unshare(CLONE_FILES), EMFILE);
		exit(0);
	}

	SAFE_WAITPID(pid, NULL, 0);
}

static void setup(void)
{
	clone3_supported_by_kernel();
}

static struct tst_test test = {
	.forks_child = 1,
	.needs_tmpdir = 1,
	.needs_root = 1,
	.test_all = run,
	.setup = setup,
	.save_restore = (const struct tst_path_val[]) {
		{FS_NR_OPEN, NULL, TST_SR_TCONF},
		{}
	},
};

#else
TST_TEST_TCONF("unshare is undefined.");
#endif
