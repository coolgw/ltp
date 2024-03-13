// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2012-2017  Red Hat, Inc.
 */

/*\
 * [Description]
 *
 * Detect heavy swapping during first time swap use.
 *
 * This case is used for testing kernel commit:
 * 50a15981a1fa ("[S390] reference bit testing for unmapped pages")
 *
 * The upstream commit fixed a issue on s390/x platform that heavy
 * swapping might occur in some condition, however since the patch
 * was quite general, this testcase will be run on all supported
 * platforms to ensure no regression been introduced.
 *
 * Details of the kernel fix:
 *
 * On x86 a page without a mapper is by definition not referenced / old.
 * The s390 architecture keeps the reference bit in the storage key and
 * the current code will check the storage key for page without a mapper.
 * This leads to an interesting effect: the first time an s390 system
 * needs to write pages to swap it only finds referenced pages. This
 * causes a lot of pages to get added and written to the swap device.
 * To avoid this behaviour change page_referenced to query the storage
 * key only if there is a mapper of the page.
 *
 * [Algorithm]
 *
 * Try to allocate memory which size is slightly larger than current
 * available memory. After allocation done, continue loop for a while
 * and calculate the used swap size. The used swap size should be small
 * enough, else it indicates that heavy swapping is occurred unexpectedly.
 */

#include <sys/types.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "tst_safe_stdio.h"
#include "mem.h"

/* allow swapping 1 * phy_mem in maximum */
#define COE_DELTA       1
/* will try to alloc 1.3 * phy_mem */
#define COE_SLIGHT_OVER 0.3

static void init_meminfo(void);
static void do_alloc(int allow_raise);
static void check_swapping(void);

static long mem_available_init;
static long swap_free_init;
static long mem_over;
static long mem_over_max;
static pid_t pid;
static unsigned int start_runtime;

static void transparent_hugepage_print(void)
{
    SAFE_FILE_PRINTF("/sys/kernel/mm/transparent_hugepage/enabled", "never");

    FILE *fp;
    char buffer[4096];  // Buffer to store the output

    // Open a pipe to run the command and read its output
    fp = popen("cat /sys/kernel/mm/transparent_hugepage/enabled", "r");
    if (fp == NULL) {
        perror("popen");
        return 1;
    }

    // Read the output and print it
    tst_res(TINFO, "====/sys/kernel/mm/transparent_hugepage/enabled====");
    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
	tst_res(TINFO, "%s", buffer);
    }

    // Close the pipe
    if (pclose(fp) == -1) {
        perror("pclose");
        return 1;
    }
}

static void vmstat_print(void)
{
    FILE *fp;
    char buffer[4096];  // Buffer to store the output

    // Open a pipe to run the command and read its output
    fp = popen("cat /proc/vmstat", "r");
    if (fp == NULL) {
        perror("popen");
        return 1;
    }

    // Read the output and print it
    tst_res(TINFO, "====/proc/vmstat====");
    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        /* printf("%s", buffer); */
	tst_res(TINFO, "%s", buffer);
    }

    // Close the pipe
    if (pclose(fp) == -1) {
        perror("pclose");
        return 1;
    }
}
static void mem_print(void)
{
    FILE *fp;
    char buffer[4096];  // Buffer to store the output

    // Open a pipe to run the command and read its output
    fp = popen("for dir in /proc/[0-9][0-9]*;do  pid=${dir##*/};name=`cat $dir/comm`;awk -v name=$name -v pid=$pid '/^Swap:/{s+=$2}END{if (s) printf \"\%dK \%s:\%d\\n\", s, name, pid}' $dir/smaps;done | sort -n -k1", "r");
    if (fp == NULL) {
        perror("popen");
        return 1;
    }

    // Read the output and print it
    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        /* printf("%s", buffer); */
	tst_res(TINFO, "%s", buffer);
    }

    // Close the pipe
    if (pclose(fp) == -1) {
        perror("pclose");
        return 1;
    }

}
static void ps_print(void)
{
    FILE *fp;
    char buffer[4096];  // Buffer to store the output

    // Open a pipe to run the command and read its output
    fp = popen("ps aux --sort=-%mem", "r");
    if (fp == NULL) {
        perror("popen");
        return 1;
    }

    // Read the output and print it
    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        /* printf("%s", buffer); */
	tst_res(TINFO, "%s", buffer);
    }

    // Close the pipe
    if (pclose(fp) == -1) {
        perror("pclose");
        return 1;
    }
}

static void pid_print(int pid)
{
    FILE *fp;
    char buffer[4096];  // Buffer to store the output

    // Open a pipe to run the command and read its output
    char cmd[128];
    sprintf(cmd, "cat /proc/%d/status", pid);
    fp = popen(cmd, "r");
    if (fp == NULL) {
        perror("popen");
        return 1;
    }

    // Read the output and print it
    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        /* printf("%s", buffer); */
	tst_res(TINFO, "%s", buffer);
    }

    // Close the pipe
    if (pclose(fp) == -1) {
        perror("pclose");
        return 1;
    }
}

static void print_summary(void)
{
	ps_print();
	mem_print();
	vmstat_print();
	TST_PRINT_MEMINFO();
}
static void test_swapping(void)
{

transparent_hugepage_print();

	FILE *file;
	char line[PATH_MAX];

	start_runtime = tst_remaining_runtime();

	file = SAFE_FOPEN("/proc/swaps", "r");
	while (fgets(line, sizeof(line), file)) {
		if (strstr(line, "/dev/zram")) {
			SAFE_FCLOSE(file);
			tst_brk(TCONF, "zram-swap is being used!");
		}
	}
	SAFE_FCLOSE(file);

	init_meminfo();

	switch (pid = SAFE_FORK()) {
	case 0:
		do_alloc(0);
		do_alloc(1);
		exit(0);
	default:
		check_swapping();
	}
}

static void init_meminfo(void)
{
	swap_free_init = SAFE_READ_MEMINFO("SwapFree:");
	mem_available_init = tst_available_mem();
	mem_over = mem_available_init * COE_SLIGHT_OVER;
	mem_over_max = mem_available_init * COE_DELTA;

	if (swap_free_init < mem_over_max)
		tst_brk(TCONF, "Not enough swap space to test: swap_free_init(%ldkB) < mem_over_max(%ldkB)",
				swap_free_init, mem_over_max);
}

static void do_alloc(int allow_raise)
{
	long mem_count;
	void *s;

	if (allow_raise == 1)
		tst_res(TINFO, "available physical memory: %ld MB",
				mem_available_init / 1024);

	mem_count = mem_available_init + mem_over;

	if (allow_raise == 1)
		tst_res(TINFO, "try to allocate: %ld MB", mem_count / 1024);
	print_summary();
	s = SAFE_MALLOC(mem_count * 1024);
	print_summary();
	memset(s, 1, mem_count * 1024);
	print_summary();

	if ((allow_raise == 1) && (raise(SIGSTOP) == -1)) {
		tst_res(TINFO, "memory allocated: %ld MB", mem_count / 1024);
		tst_brk(TBROK | TERRNO, "kill");
	}

	free(s);
}

static void check_swapping(void)
{
	int status;
	long swap_free_now, swapped;

	/* wait child stop */
	SAFE_WAITPID(pid, &status, WUNTRACED);
	if (!WIFSTOPPED(status))
		tst_brk(TBROK, "child was not stopped.");

	/* Still occupying memory, loop for a while */
	while (tst_remaining_runtime() > start_runtime/2) {
		swap_free_now = SAFE_READ_MEMINFO("SwapFree:");
		sleep(1);
		long diff = labs(swap_free_now - SAFE_READ_MEMINFO("SwapFree:"));

		if (diff < 10)
			break;

		tst_res(TINFO, "SwapFree difference %li", diff);
	}

	swapped = SAFE_READ_PROC_STATUS(pid, "VmSwap:");
	/* tst_res(TINFO, "!!!!!!!!after mem alocate!!!!!!!!!!"); */
	pid_print(pid);
	/* ps_print(); */
	/* mem_print(); */
	/* TST_PRINT_MEMINFO(); */
	if (swapped > mem_over_max) {
		kill(pid, SIGCONT);
		tst_brk(TFAIL, "heavy swapping detected: %ld MB swapped",
				swapped / 1024);
	}

	tst_res(TPASS, "no heavy swapping detected, %ld MB swapped.",
		 swapped / 1024);
	kill(pid, SIGCONT);
	/* wait child exit */
	SAFE_WAITPID(pid, &status, 0);
}

static struct tst_test test = {
	.needs_root = 1,
	.forks_child = 1,
	.min_mem_avail = 10,
	.max_runtime = 600,
	.test_all = test_swapping,
	.skip_in_compat = 1,
	.needs_kconfigs = (const char *[]) {
		"CONFIG_SWAP=y",
		NULL
	},
	.tags = (const struct tst_tag[]) {
		{"linux-git", "50a15981a1fa"},
		{}
	}
};
