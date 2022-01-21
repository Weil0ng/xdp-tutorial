// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2017 - 2018 Intel Corporation. */

#include <errno.h>
#include <getopt.h>
#include <libgen.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/xsk.h>
#include "xdpsock.h"

void cleanup() {
	unlink(SOCKET_NAME);
	exit(EXIT_FAILURE);
}

#define handle_error(msg) { fprintf(stderr, "%s %s(%d)\n", msg, strerror(errno), errno); cleanup(); }

static const char *opt_if = "";
static int opt_map_id;

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
			opt_map_id = atoi(optarg);
			break;
		default:
			usage(basename(argv[0]));
		}
	}
}

static int send_xsk_fd(int sock, int fd)
{
	char cmsgbuf[CMSG_SPACE(sizeof(int))];
	struct msghdr msg;
	struct iovec iov;
	int value = 0;

	if (fd == -1) {
		fprintf(stderr, "Incorrect fd = %d\n", fd);
		return -1;
	}
	iov.iov_base = &value;
	iov.iov_len = sizeof(int);

	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_flags = 0;
	msg.msg_control = cmsgbuf;
	msg.msg_controllen = CMSG_LEN(sizeof(int));

	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);

	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));

	*(int *)CMSG_DATA(cmsg) = fd;
	int ret = sendmsg(sock, &msg, 0);

	return ret;
}

int open_xsk_socket() {
	int fd;

	fd = socket(AF_XDP, SOCK_RAW | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		handle_error("open socket failed");
	}
	return fd;
}

int bind_xsk_socket(int fd, int ifindex, int qid) {
	struct sockaddr_xdp sxdp = {};

        sxdp.sxdp_family = PF_XDP; 
	sxdp.sxdp_ifindex = ifindex;
	sxdp.sxdp_queue_id = qid;
	sxdp.sxdp_flags = XDP_USE_NEED_WAKEUP | XDP_FLAGS_SKB_MODE;
	printf("Binding %d to ifindex %d queue %d\n", fd, ifindex, qid);
	if (bind(fd, (struct sockaddr *)&sxdp, sizeof(struct sockaddr_xdp))) {
		handle_error("bind socket failed");
	}
	return 0;
}

int update_xsk_map(int map_fd, int *qid, int *socket_fd) {
	if(bpf_map_update_elem(map_fd, qid, socket_fd, 0)) {
		handle_error("Updating xsk map failed");
	}
	return 0;
}

int recv_setup_done(int sock) {
	char buf[1024];
	read(sock, buf, sizeof(buf));
	
	// We don't care about the actual content.
	return 0;
}

int
main(int argc, char **argv)
{
	struct sockaddr_un server;
	int ifindex = 0, queue_id=0;
	int flag = 1;
	int sock;
	int err;
	int socket_fd, dup_fd;
	int xsks_map_fd;

	parse_command_line(argc, argv);

	ifindex = if_nametoindex(opt_if);
	if (ifindex == 0) {
		handle_error("Unable to get ifindex");
	}

	// Step 1: open domain socket to transmit fds later.
	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		handle_error("Unable to open domain socket");
	}

	server.sun_family = AF_UNIX;
	strcpy(server.sun_path, SOCKET_NAME);

	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(int));

	if (connect(sock, (struct sockaddr *)&server, sizeof(struct sockaddr_un))) {
		handle_error("Connecting to domain socket failed");
	}

	// Step 2: open af_xdp socket
	socket_fd = open_xsk_socket(ifindex, queue_id);
	if (socket_fd < 0) {
		handle_error("Failed to open socket fd");
	}
	printf("Created xdp socket fd: %d\n", socket_fd);

	// Step 3: send socket fd to container
	dup_fd = dup(socket_fd);
	err = send_xsk_fd(sock, dup_fd);
	if (err < 0) {
		handle_error("Send socket fd failed");
	}

	// Step 4: get setup completion from container
	err = recv_setup_done(sock);
	if (err < 0) {
		handle_error("Recv setup completion failed");
	}
	
        // Step 5: bind socket
	err = bind_xsk_socket(socket_fd, ifindex, queue_id);
	if (err) {
		handle_error("Bind socket failed");
	}

	// Step 6: load xdp prog
	/*
	err = xsk_setup_xdp_prog(ifindex, &xsks_map_fd);
	if (err) {
		handle_error("Setup of xdp program failed");
	}
	*/

	// Step 7: update xsk map
	xsks_map_fd = bpf_map_get_fd_by_id(opt_map_id); 
	err = update_xsk_map(xsks_map_fd, &queue_id, &socket_fd);
	if (err) {
		handle_error("Update xsk map failed");
	}

	close(sock);

	/* Unset fd for given ifindex */
	err = bpf_set_link_xdp_fd(ifindex, -1, 0);
	if (err) {
		fprintf(stderr, "Error when unsetting bpf prog_fd for ifindex(%d)\n", ifindex);
		return err;
	}

	while(1){};

	return 0;
}
