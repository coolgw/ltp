// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) International Business Machines  Corp., 2001
 * Copyright (c) 2025 Wei Gao <wegao@suse.com>
 */

/*\
 * LTP test case verify that connect() returns the expected errno
 * for various failure cases and the also validates successful connections
 * to various server types.
 */

#include "tst_test.h"

static int s;			/* socket descriptor */
static struct sockaddr_in sin1, sin2, sin3, sin4;
static int sfd;			/* shared between start_server and do_child */
static pid_t pid;

static void setup(void);
static void setup0(unsigned int testno);
static void setup1(unsigned int testno);
static void setup2(unsigned int testno);
static void cleanup0(void);
static void cleanup1(void);
static void do_child(void);
static pid_t start_server(int domain, int type, struct sockaddr_in *);

struct test_case_t {		/* test case structure */
	int domain;		/* PF_INET, PF_UNIX, ... */
	int type;		/* SOCK_STREAM, SOCK_DGRAM ... */
	int proto;		/* protocol number (usually 0 = default) */
	struct sockaddr *sockaddr;	/* socket address buffer */
	int salen;		/* connect's 3rd argument */
	int retval;		/* syscall return value */
	int experrno;		/* expected errno */
	void (*setup)(unsigned int testno);
	void (*cleanup)(void);
	char *desc;
} tdat[] = {
	{
	PF_INET, SOCK_STREAM, 0, (struct sockaddr *)&sin1,
		    sizeof(struct sockaddr_in), -1, EBADF, setup0,
		    cleanup0, "bad file descriptor"},
	{
	PF_INET, SOCK_STREAM, 0, (struct sockaddr *)-1,
		    sizeof(struct sockaddr_in), -1, EFAULT, setup1,
		    cleanup1, "invalid socket buffer"},
	{
	PF_INET, SOCK_STREAM, 0, (struct sockaddr *)&sin1,
		    3, -1, EINVAL, setup1, cleanup1, "invalid salen"},
	{
	PF_INET, SOCK_STREAM, 0, (struct sockaddr *)&sin1,
		    sizeof(sin1), -1, ENOTSOCK, setup0, cleanup0,
		    "invalid socket"},
	{
	PF_INET, SOCK_STREAM, 0, (struct sockaddr *)&sin1,
		    sizeof(sin1), -1, EISCONN, setup2, cleanup1,
		    "already connected"},
	{
	PF_INET, SOCK_STREAM, 0, (struct sockaddr *)&sin2,
		    sizeof(sin2), -1, ECONNREFUSED, setup1, cleanup1,
		    "connection refused"},
	{
	PF_INET, SOCK_STREAM, 0, (struct sockaddr *)&sin4,
		    sizeof(sin4), -1, EAFNOSUPPORT, setup1, cleanup1,
		    "invalid address family"},
	{
	PF_INET, SOCK_STREAM, 0, (struct sockaddr *)&sin1,
		sizeof(sin1), 0, 0, setup1, cleanup1,
		"valid stream connection"},
	{
	PF_INET, SOCK_DGRAM, 0, (struct sockaddr *)&sin1,
		sizeof(sin1), 0, 0, setup1, cleanup1,
		"valid datagram connection"},
};

/**
 * bionic's connect() implementation calls netdClientInitConnect() before
 * sending the request to the kernel.  We need to bypass this, or the test will
 * segfault during the addr = (struct sockaddr *)-1 testcase. We had cases where
 * tests started to segfault on glibc upgrade or in special conditions where
 * libc had to convert structure layouts between 32bit/64bit userspace/kernel =>
 * safer to call the raw syscall regardless of the libc implementation.
 */
#include "lapi/syscalls.h"

static int sys_connect(int sockfd, const struct sockaddr *addr,
		socklen_t addrlen)
{
	return tst_syscall(__NR_connect, sockfd, addr, addrlen);
}

#define connect(sockfd, addr, addrlen) sys_connect(sockfd, addr, addrlen)

static void verify_accept(unsigned int testno)
{
	pid = start_server(tdat[testno].domain, tdat[testno].type, &sin1);

	setup();

	tdat[testno].setup(testno);

	TEST(connect(s, tdat[testno].sockaddr, tdat[testno].salen));

	if (TST_RET != tdat[testno].retval ||
			(TST_RET < 0 &&
			 TST_ERR != tdat[testno].experrno)) {
		tst_res(TFAIL, "%s ; returned"
				" %ld (expected %d), errno %d (expected"
				" %d)", tdat[testno].desc,
				TST_RET, tdat[testno].retval,
				TST_ERR, tdat[testno].experrno);
	} else {
		tst_res(TPASS, "%s successful", tdat[testno].desc);
	}

	tdat[testno].cleanup();
}


static void setup(void)
{

	sin2.sin_family = AF_INET;
	/* this port must be unused! */
	sin2.sin_port = TST_GET_UNUSED_PORT(AF_INET, SOCK_STREAM);
	sin2.sin_addr.s_addr = INADDR_ANY;

	sin3.sin_family = AF_INET;
	sin3.sin_port = 0;
	/* assumes no route to this network! */
	sin3.sin_addr.s_addr = htonl(0x0AFFFEFD);

	sin4.sin_family = 47;	/* bogus address family */
	sin4.sin_port = 0;
	sin4.sin_addr.s_addr = htonl(0x0AFFFEFD);

}

static void setup0(unsigned int testno)
{
	if (tdat[testno].experrno == EBADF)
		s = 400;	/* anything not an open file */
	else
		s = SAFE_OPEN("/dev/null", O_WRONLY);

}

static void cleanup0(void)
{
	close(s);
	s = -1;
}

static void setup1(unsigned int testno)
{
	s = SAFE_SOCKET(tdat[testno].domain, tdat[testno].type,
		tdat[testno].proto);
}

static void cleanup1(void)
{
	(void)close(s);
	s = -1;
}

static void setup2(unsigned int testno)
{
	setup1(testno);		/* get a socket in s */
	SAFE_CONNECT(s, (const struct sockaddr *)&sin1, sizeof(sin1));
}

static pid_t start_server(int domain, int type, struct sockaddr_in *sin0)
{
	pid_t pid;
	socklen_t slen = sizeof(*sin0);

	sin0->sin_family = AF_INET;
	sin0->sin_port = 0; /* pick random free port */
	sin0->sin_addr.s_addr = INADDR_ANY;

	sfd = socket(domain, type, 0);
	if (sfd < 0) {
		tst_brk(TBROK | TERRNO, "server socket failed");
		return -1;
	}
	if (bind(sfd, (struct sockaddr *)sin0, sizeof(*sin0)) < 0) {
		tst_brk(TBROK | TERRNO, "server bind failed");
		return -1;
	}

	if (type != SOCK_DGRAM) {
		if (listen(sfd, 10) < 0) {
			tst_brk(TBROK | TERRNO, "server listen failed");
			return -1;
		}
	}

	SAFE_GETSOCKNAME(sfd, (struct sockaddr *)sin0, &slen);

	switch ((pid = SAFE_FORK())) {
	case 0:		/* child */
		do_child();
		break;
	case -1:
		tst_brk(TBROK | TERRNO, "server fork failed");
		/* fall through */
	default:		/* parent */
		(void)close(sfd);
		return pid;
	}

	return -1;
}

static void do_child(void)
{
	struct sockaddr_in fsin;
	fd_set afds, rfds;
	int nfds, cc, fd;
	char c;

	FD_ZERO(&afds);
	FD_SET(sfd, &afds);

	nfds = sfd + 1;

	struct timeval timeout;

	timeout.tv_sec = 0;
	timeout.tv_usec = 100;

	socklen_t fromlen;

	memcpy(&rfds, &afds, sizeof(rfds));

	if (select(nfds, &rfds, NULL, NULL, &timeout) < 0)
		exit(0);

	if (FD_ISSET(sfd, &rfds)) {
		int newfd;

		fromlen = sizeof(fsin);
		newfd = accept(sfd, (struct sockaddr *)&fsin, &fromlen);
		if (newfd >= 0) {
			FD_SET(newfd, &afds);
			nfds = MAX(nfds, newfd + 1);
		}
	}
	for (fd = 0; fd < nfds; ++fd)
		if (fd != sfd && FD_ISSET(fd, &rfds)) {
			cc = read(fd, &c, 1);
			if (cc == 0) {
				(void)close(fd);
				FD_CLR(fd, &afds);
			}
		}

	exit(0);
}

static struct tst_test test = {
	.tcnt = ARRAY_SIZE(tdat),
	.test = verify_accept,
	.forks_child = 1,
};
