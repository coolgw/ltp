// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2023 Wei Gao <wegao@suse.com>
 */

/*\
 * Verify disallows open of FIFOs or regular files not owned by the user in world
 * writable sticky directories
 */

#include <pwd.h>
#include <stdlib.h>
#include "tst_test.h"
#include "tst_safe_file_at.h"

#define  FILENAME  "setuid04_testfile"
#define  DIR "ltp_tmp_check1"
#define  TEST_FILE "test_file_1"
#define  TEST_FIFO "test_fifo_1"
#define  LTP_USR_UID1 1000
#define  LTP_USR_UID2 1001
#define  CONCAT(dir, filename) dir "/" filename
#define  PROTECTED_REGULAR "/proc/sys/fs/protected_regular"
#define  PROTECTED_FIFOS "/proc/sys/fs/protected_fifos"

static int dir_fd;

static void run(void)
{
	SAFE_CHMOD(DIR, 0777 | S_ISVTX);
	SAFE_FILE_PRINTF(PROTECTED_REGULAR, "%d", 0);
	SAFE_FILE_PRINTF(PROTECTED_FIFOS, "%d", 0);

	if (!SAFE_FORK()) {
		SAFE_SETUID(LTP_USR_UID1);

		int fd = TST_EXP_FD(openat(dir_fd, TEST_FILE, O_CREAT | O_RDWR, 0777));

		SAFE_CLOSE(fd);

		SAFE_MKFIFO(CONCAT(DIR, TEST_FIFO), 0777);

		exit(0);
	}

	tst_reap_children();

	if (!SAFE_FORK()) {
		SAFE_SETUID(LTP_USR_UID2);

		int fd = TST_EXP_FD(openat(dir_fd, TEST_FILE, O_CREAT | O_RDWR, 0777));

		SAFE_CLOSE(fd);

		fd = TST_EXP_FD(open(CONCAT(DIR, TEST_FIFO), O_RDWR | O_CREAT, 0777));
		SAFE_CLOSE(fd);

		exit(0);
	}

	tst_reap_children();

	SAFE_FILE_PRINTF(PROTECTED_REGULAR, "%d", 1);
	SAFE_FILE_PRINTF(PROTECTED_FIFOS, "%d", 1);

	if (!SAFE_FORK()) {
		SAFE_SETUID(LTP_USR_UID2);
		TST_EXP_FAIL(openat(dir_fd, TEST_FILE, O_RDWR | O_CREAT, 0777), EACCES);
		TST_EXP_FAIL(open(CONCAT(DIR, TEST_FIFO), O_RDWR | O_CREAT, 0777), EACCES);

		exit(0);
	}

	tst_reap_children();

	SAFE_FILE_PRINTF(PROTECTED_REGULAR, "%d", 2);
	SAFE_FILE_PRINTF(PROTECTED_FIFOS, "%d", 2);
	SAFE_CHMOD(DIR, 0020 | S_ISVTX);

	if (!SAFE_FORK()) {
		SAFE_SETUID(LTP_USR_UID2);
		TST_EXP_FAIL(openat(dir_fd, TEST_FILE, O_RDWR | O_CREAT, 0777), EACCES);
		TST_EXP_FAIL(open(CONCAT(DIR, TEST_FIFO), O_RDWR | O_CREAT, 0777), EACCES);

		exit(0);
	}

	tst_reap_children();
	SAFE_UNLINK(CONCAT(DIR, TEST_FIFO));
}

static void setup(void)
{
	umask(0);
	SAFE_MKDIR(DIR, 0777 | S_ISVTX);
	dir_fd = SAFE_OPEN(DIR, O_DIRECTORY);
}

static void cleanup(void)
{
	if (dir_fd != -1)
		SAFE_CLOSE(dir_fd);
}

static struct tst_test test = {
	.setup = setup,
	.cleanup = cleanup,
	.needs_root = 1,
	.test_all = run,
	.needs_tmpdir = 1,
	.forks_child = 1,
	.save_restore = (const struct tst_path_val[]) {
		{PROTECTED_REGULAR, NULL, TST_SR_TCONF},
		{PROTECTED_FIFOS, NULL, TST_SR_TCONF},
		{}
	},
	.tags = (const struct tst_tag[]) {
		{"linux-git", "30aba6656f61ed44cba445a3c0d38b296fa9e8f5"},
		{}
	}
};
