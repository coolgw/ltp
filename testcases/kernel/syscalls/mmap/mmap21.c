// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2024 Wei Gao <wegao@suse.com>
 */

/*\
 * [Description]
 *
 * Test mmap(2) with MAP_DROPPABLE flag.
 *
 * Test base on kernel selftests/mm/droppable.c
 */

#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <sys/types.h>
#include "tst_test.h"
#include "lapi/mmap.h"

#define MEM_LIMIT (256 * TST_MB)
#define ALLOC_SIZE (128 * TST_MB)

static struct tst_cg_group *cg_child;

static void test_mmap(void)
{
	size_t alloc_size = ALLOC_SIZE;
	size_t page_size = getpagesize();
	void *alloc;
	pid_t child;

	cg_child = tst_cg_group_mk(tst_cg, "child");
	SAFE_CG_PRINTF(tst_cg, "memory.max", "%d", MEM_LIMIT);
	SAFE_CG_PRINTF(cg_child, "cgroup.procs", "%d", getpid());

	alloc = SAFE_MMAP(0, alloc_size, PROT_READ | PROT_WRITE,
			MAP_ANONYMOUS | MAP_DROPPABLE, -1, 0);

	memset(alloc, 'A', alloc_size);
	for (size_t i = 0; i < alloc_size; i += page_size) {
		if (*(char *)(alloc + i) != 'A')
			tst_res(TFAIL, "memset failed");
	}

	int *shared_var = SAFE_MMAP(NULL, sizeof(int), PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_ANONYMOUS, -1, 0);

	*shared_var = 0;

	child = SAFE_FORK();
	if (!child) {
		for (;;) {
			*(char *)malloc(page_size) = 'B';
			if ((*shared_var) == 1)
				exit(0);
		}
	}

	while (!(*shared_var)) {
		for (size_t i = 0; i < alloc_size; i += page_size) {
			if (!*(uint8_t *)(alloc + i)) {
				*shared_var = 1;
				break;
			}
		}
	}

	TST_EXP_EQ_LI((*shared_var), 1);

	SAFE_WAITPID(child, NULL, 0);

	SAFE_MUNMAP(alloc, alloc_size);
	SAFE_MUNMAP(shared_var, sizeof(int));
}

static void setup(void)
{
	void *addr = mmap(0, 1, PROT_READ | PROT_WRITE,
			MAP_ANONYMOUS | MAP_DROPPABLE, -1, 0);
	if (addr == MAP_FAILED && errno == EINVAL)
		tst_brk(TCONF, "MAP_DROPPABLE not support");
}

static void cleanup(void)
{
	if (cg_child) {
		SAFE_CG_PRINTF(tst_cg_drain, "cgroup.procs", "%d", getpid());
		cg_child = tst_cg_group_rm(cg_child);
	}
}

static struct tst_test test = {
	.test_all = test_mmap,
	.needs_tmpdir = 1,
	.forks_child = 1,
	.needs_cgroup_ctrls = (const char *const []){ "memory", NULL },
	.needs_root = 1,
	.cleanup = cleanup,
	.setup = setup,
	.min_mem_avail = 300,
};
