// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2017 - 2018 Intel Corporation. */

#include <errno.h>
#include <getopt.h>
#include <libgen.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/xsk.h>
#include "xdpsock.h"

static const char *opt_if = "";
static int opt_map;

static struct option long_options[] = {
	{"interface", required_argument, 0, 'i'},
	{0, 0, 0, 0}
};

static void usage(const char *prog)
{
	const char *str =
		"  Usage: %s [OPTIONS]\n"
		"  Options:\n"
		"  -i, --interface=n	Run on interface n\n"
		"\n";
	fprintf(stderr, "%s\n", str);

	exit(0);
}

static void parse_command_line(int argc, char **argv)
{
	int option_index, c;

	opterr = 0;

	for (;;) {
		c = getopt_long(argc, argv, "i:m:",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'i':
			opt_if = optarg;
			break;
		case 'm':
			opt_map = atoi(optarg);
			break;
		default:
			usage(basename(argv[0]));
		}
	}
}

static
int *recv_fds(int socket, int n) {
        int *fds = malloc(n * sizeof(int));
        struct msghdr msg = {0};
        struct cmsghdr *cmsg;
        char buf[CMSG_SPACE(n * sizeof(int))], dup[256];
        memset(buf, '\0', sizeof(buf));
        struct iovec io = { .iov_base = &dup, .iov_len = sizeof(dup) };

        msg.msg_iov = &io;
        msg.msg_iovlen = 1;
        msg.msg_control = buf;
        msg.msg_controllen = sizeof(buf);

        if (recvmsg(socket, &msg, 0) < 0) {
		fprintf(stderr, "Recvmsg failed: %s\n", strerror(errno));
		return -errno;
	}

        cmsg = CMSG_FIRSTHDR(&msg);

        memcpy(fds, (int *)CMSG_DATA(cmsg), n * sizeof(int));

        return fds;
}

static
int *recv_xsk_fds(int n) {
        ssize_t nbytes;
        char buffer[256];
        int sfd, cfd;
        int *fds;
        struct sockaddr_un addr;

	unlink(SOCKET_NAME);

        sfd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (sfd < 0) {
		fprintf(stderr, "Openning socket stream failed: %s\n", strerror(errno));
		return -errno;
	}

        memset(&addr, 0, sizeof(struct sockaddr_un));
        addr.sun_family = AF_UNIX;
        strcpy(addr.sun_path, SOCKET_NAME);

        if (bind(sfd, (struct sockaddr *) &addr, sizeof(struct sockaddr_un))) {
		fprintf(stderr, "Binding to socket failed: %s\n", strerror(errno));
		return -errno;
	}

        if (listen(sfd, 5) < 0) {
		fprintf(stderr, "Listening to socket failed: %s\n", strerror(errno));
		return -errno;
	}

        cfd = accept(sfd, NULL, NULL);
        if (cfd == -1) {
		fprintf(stderr, "Accepting socket failed: %s\n", strerror(errno));
		return -errno;
	}

        fds = recv_fds(cfd, n);

        fprintf(stdout, "Reading socket fd: %d, queue id: %d\n", fds[0], fds[1]);

        if (close(cfd) < 0) {
		fprintf(stderr, "Closing socket failed: %s\n", strerror(errno));
		return -errno;
	}

        return fds;
}

int
main(int argc, char **argv)
{
	struct sockaddr_un server;
	int listening = 1;
	int rval, msgsock;
	int ifindex = 0;
	int flag = 1;
	int cmd = 0;
	int sock;
	int err;
	int *fds;
	int map_fd;

	parse_command_line(argc, argv);

	fds = recv_xsk_fds(2);
	map_fd = bpf_map_get_fd_by_id(opt_map);
	fprintf(stdout, "map fd: %d\n", map_fd);
	fprintf(stdout, "Update queue id: %d, with socket fd: %d\n", fds[1], fds[0]);
	bpf_map_update_elem(map_fd, &fds[1], &fds[0], 0);
	while (listening) {}
	close(sock);
	unlink(SOCKET_NAME);

	/* Unset fd for given ifindex */
	err = bpf_set_link_xdp_fd(ifindex, -1, 0);
	if (err) {
		fprintf(stderr, "Error when unsetting bpf prog_fd for ifindex(%d)\n", ifindex);
		return err;
	}

	return 0;

close_sock:
	close(sock);
	unlink(SOCKET_NAME);
	return err;
}
