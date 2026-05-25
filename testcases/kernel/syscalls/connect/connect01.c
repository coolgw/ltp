// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) International Business Machines  Corp., 2001
 * Copyright (c) Linux Test Project, 2006-2026
 */

/*\
 * Verify that connect() returns the proper errno for various failure cases.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include "tst_test.h"
#include "lapi/syscalls.h"

static int fd_invalid = -1;
static int fd_socket;
static int fd_null;
static int fd_connected;
static int fd_server;

static struct sockaddr_in sock1;
static struct sockaddr_in sock2;
static struct sockaddr_in sock3;
static void *bad_addr;

static pid_t pid;

static struct test_case_t {
	int *fd;
	void *addr;
	socklen_t salen;
	int exp_errno;
	char *desc;
} tcases[] = {
	{&fd_invalid, &sock1, sizeof(sock1), EBADF,
		"sockfd is not a valid open file descriptor"},
	{&fd_socket, NULL, sizeof(sock1), EFAULT,
		"socket structure address is outside the user's address space"},
	{&fd_socket, &sock1, 3, EINVAL,
		"addrlen is not valid"},
	{&fd_null, &sock1, sizeof(sock1), ENOTSOCK,
		"file descriptor sockfd does not refer to a socket"},
	{&fd_connected, &sock1, sizeof(sock1), EISCONN,
		"socket is already connected"},
	{&fd_socket, &sock2, sizeof(sock2), ECONNREFUSED,
		"connect on a socket found no one listening on remote address"},
	{&fd_socket, &sock3, sizeof(sock3), EAFNOSUPPORT,
		"address doesn't have the correct address family in sa_family"},
};

static int sys_connect(int sockfd, const struct sockaddr *addr,
		socklen_t addrlen)
{
	return tst_syscall(__NR_connect, sockfd, addr, addrlen);
}

static void start_server(struct sockaddr_in *sock)
{
	socklen_t slen = sizeof(*sock);

	sock->sin_family = AF_INET;
	sock->sin_port = 0;
	sock->sin_addr.s_addr = INADDR_ANY;

	fd_server = SAFE_SOCKET(PF_INET, SOCK_STREAM, 0);
	SAFE_BIND(fd_server, (struct sockaddr *)sock, slen);
	SAFE_LISTEN(fd_server, 10);
	SAFE_GETSOCKNAME(fd_server, (struct sockaddr *)sock, &slen);

	pid = SAFE_FORK();

	if (!pid) {
		int nfd = SAFE_ACCEPT(fd_server, NULL, NULL);

		SAFE_CLOSE(nfd);
		exit(0);
	}
	SAFE_CLOSE(fd_server);
}

static void setup(void)
{
	bad_addr = tst_get_bad_addr(NULL);
	start_server(&sock1);

	fd_socket = SAFE_SOCKET(PF_INET, SOCK_STREAM, 0);
	fd_null = SAFE_OPEN("/dev/null", O_WRONLY);

	fd_connected = SAFE_SOCKET(PF_INET, SOCK_STREAM, 0);
	SAFE_CONNECT(fd_connected, (const struct sockaddr *)&sock1, sizeof(sock1));

	/* Wait for server to accept and exit */
	SAFE_WAITPID(pid, NULL, 0);
	pid = 0;

	sock2.sin_family = AF_INET;
	sock2.sin_port = TST_GET_UNUSED_PORT(AF_INET, SOCK_STREAM);
	sock2.sin_addr.s_addr = INADDR_ANY;

	sock3.sin_family = 47;
	sock3.sin_port = 0;
	sock3.sin_addr.s_addr = htonl(0x0AFFFEFD);
}

static void cleanup(void)
{
	if (fd_socket > 0)
		SAFE_CLOSE(fd_socket);
	if (fd_null > 0)
		SAFE_CLOSE(fd_null);
	if (fd_connected > 0)
		SAFE_CLOSE(fd_connected);

	if (pid > 0) {
		SAFE_KILL(pid, SIGKILL);
		SAFE_WAITPID(pid, NULL, 0);
	}
}

static void verify_connect(unsigned int i)
{
	struct test_case_t *tc = &tcases[i];
	void *addr = tc->addr ? tc->addr : bad_addr;

	TST_EXP_FAIL(sys_connect(*tc->fd, addr, tc->salen),
		tc->exp_errno, "%s", tc->desc);
}

static struct tst_test test = {
	.setup = setup,
	.cleanup = cleanup,
	.tcnt = ARRAY_SIZE(tcases),
	.test = verify_connect,
	.forks_child = 1,
};
