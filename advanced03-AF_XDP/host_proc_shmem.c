// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2017 - 2018 Intel Corporation. */

#include <errno.h>
#include <getopt.h>
#include <libgen.h>
#include <linux/if_link.h>
#include <linux/limits.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <unistd.h>
#include <fcntl.h>

#include <bpf/bpf.h>
#include <bpf/xsk.h>
#include "xdpsock.h"

#define NUM_FRAMES 128

void cleanup() {
	unlink(SOCKET_NAME1);
	unlink(SOCKET_NAME2);
	exit(EXIT_FAILURE);
}

#define handle_error(msg) { fprintf(stderr, "%s %s(%d)\n", msg, strerror(errno), errno); cleanup(); }

static const char *opt_if = "";
static int opt_map_id;
static int opt_queue;
static int opt_xsk_frame_size = XSK_UMEM__DEFAULT_FRAME_SIZE;
static u32 opt_xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
static u32 opt_xdp_bind_flags = XDP_USE_NEED_WAKEUP;
static u32 opt_umem_flags;

struct xsk_umem_info {
	struct xsk_ring_prod fq;
	struct xsk_ring_cons cq;
	struct xsk_umem *umem;
	void *buffer;
};

struct xsk_socket_info {
	struct xsk_ring_cons rx;
	struct xsk_ring_prod tx;
	struct xsk_umem_info *umem;
	struct xsk_socket *xsk;
};

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
	fprintf(stdout, "Binding %d to ifindex %d queue %d\n", fd, ifindex, qid);
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

static struct xsk_umem_info *xsk_configure_umem(void *buffer, u64 size) {
	struct xsk_umem_info *umem;
	struct xsk_umem_config cfg = {
		.fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS * 2,
		.comp_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
		.frame_size = opt_xsk_frame_size,
		.frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
		.flags = opt_umem_flags
	};
	int ret;

	umem = calloc(1, sizeof(*umem));
	if (!umem) {
		handle_error("Failed to allocate umem struct");
	}

	ret = xsk_umem__create(&umem->umem, buffer, size, &umem->fq, &umem->cq, &cfg);
	if (ret) {
		handle_error("Failed to configure umem");
	}
	umem->buffer = buffer;
	return umem;
}

static struct xsk_socket_info *xsk_configure_socket(struct xsk_umem_info *umem,
				       		    bool rx, bool tx) {
	struct xsk_socket_config cfg;
	struct xsk_socket_info *xsk;
	struct xsk_ring_cons *rxr;
	struct xsk_ring_prod *txr;
	int ret;

	xsk = calloc(1, sizeof(*xsk));
	if (!xsk) {
		handle_error("Failed to alloc xsk_socket_info");
	}

	xsk->umem = umem;

	cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
	cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
	cfg.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD;
	cfg.xdp_flags = opt_xdp_flags;
	cfg.bind_flags = opt_xdp_bind_flags;

	rxr = rx ? &xsk->rx : NULL;
	txr = tx ? &xsk->tx : NULL;

	ret = xsk_socket__create_no_map(&xsk->xsk, opt_if, opt_queue, umem->umem, rxr, txr, &cfg);
	if (ret) {
		handle_error("Failed to create xsk_socket");
	}
	return xsk;
}

static void xsk_populate_fill_ring(struct xsk_umem_info *umem) {
	int ret, i;
	u32 idx;

	ret = xsk_ring_prod__reserve(&umem->fq,
			XSK_RING_PROD__DEFAULT_NUM_DESCS * 2, &idx);
	if (ret != XSK_RING_PROD__DEFAULT_NUM_DESCS * 2)
		handle_error("Failed to populate fill ring");
	for (i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS * 2;  i++) {
		*xsk_ring_prod__fill_addr(&umem->fq, idx++) = i * opt_xsk_frame_size;
	}
	xsk_ring_prod__submit(&umem->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS * 2);
}

int
main(int argc, char **argv)
{
	struct sockaddr_un server;
	int ifindex = 0, queue_id=0;
	int flag = 1;
	int sock1, sock2;
	int err;
	int socket_fd1, dup_fd1, socket_fd2, dup_fd2, dup_umem_fd1, dup_umem_fd2;
	int xsks_map_fd;
        struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	void *bufs;
	int umem_fd;
	struct xsk_umem_info *umem;
	struct xsk_socket_info *xsk1, *xsk2;

	parse_command_line(argc, argv);

	ifindex = if_nametoindex(opt_if);
	if (ifindex == 0) {
		handle_error("Unable to get ifindex");
	}

	// Step 1: create shared umem
	if (setrlimit(RLIMIT_MEMLOCK, &r)) {
		handle_error("Failed to set rlimit for MEMLOCK");
	}
	// https://stackoverflow.com/questions/11909505/posix-shared-memory-and-semaphores-permissions-set-incorrectly-by-open-calls
	mode_t old_umask = umask(0);
	umem_fd = shm_open("umem", O_CREAT | O_RDWR, 0777);
	umask(old_umask);
	if (umem_fd < 0) {
		handle_error("Failed to open file for shared umem under /dev/shm");
	}
	err = ftruncate(umem_fd, NUM_FRAMES * opt_xsk_frame_size);
	if (err < 0) {
		handle_error("Failed to ftruncate umem");
	}

        bufs = mmap(NULL, NUM_FRAMES * opt_xsk_frame_size,
			PROT_READ | PROT_WRITE, MAP_SHARED,
			umem_fd, 0);
	if (bufs == MAP_FAILED) {
		handle_error("Failed to mmap /dev/shm to umem");
	}
	umem = xsk_configure_umem(bufs, NUM_FRAMES * opt_xsk_frame_size);

	xsk_populate_fill_ring(umem);

	// Step 2: open domain socket to transmit fds later.
	sock1 = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock1 < 0) {
		handle_error("Unable to open domain socket1");
	}

	server.sun_family = AF_UNIX;
	strcpy(server.sun_path, SOCKET_NAME1);

	setsockopt(sock1, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(int));

	if (connect(sock1, (struct sockaddr *)&server, sizeof(struct sockaddr_un))) {
		handle_error("Connecting to domain socket1 failed");
	}

	sock2 = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock2 < 0) {
		handle_error("Unable to open domain socket2");
	}

	server.sun_family = AF_UNIX;
	strcpy(server.sun_path, SOCKET_NAME2);

	setsockopt(sock2, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(int));

	if (connect(sock2, (struct sockaddr *)&server, sizeof(struct sockaddr_un))) {
		handle_error("Connecting to domain socket2 failed");
	}


	// Step 3.1: create 1st socket for shm1
	xsk1 = xsk_configure_socket(umem, true, true);
	socket_fd1 = xsk_socket__fd(xsk1->xsk);
	printf("Created xdp socket fd1: %d\n", socket_fd1);

	// Step 3.3: create 2nd socket for shm1
	xsk2 = xsk_configure_socket(umem, true, true);
	socket_fd2 = xsk_socket__fd(xsk2->xsk);
	printf("Created xdp socket fd2: %d\n", socket_fd2);

	// Step 3.2: send socket_fd1 to container shm1
	dup_fd1 = dup(socket_fd1);
	printf("Duplicating fd %d to %d\n", socket_fd1, dup_fd1);
	err = send_xsk_fd(sock1, dup_fd1);
	if (err < 0) {
		handle_error("Send socket_fd1 failed");
	}
	dup_umem_fd1 = dup(umem_fd);
	printf("Duplicating fd %d to %d\n", umem_fd, dup_umem_fd1);
	err = send_xsk_fd(sock1, dup_umem_fd1);
	if (err < 0) {
		handle_error("Send dup_umem_fd1 failed");
	}
	
	// Step 3.4: send socket_fd2 to container shm2
	dup_fd2 = dup(socket_fd2);
	printf("Duplicating fd %d to %d\n", socket_fd2, dup_fd2);
	err = send_xsk_fd(sock2, dup_fd2);
	if (err < 0) {
		handle_error("Send socket_fd2 failed");
	}
	dup_umem_fd2 = dup(umem_fd);
	printf("Duplicating fd %d to %d\n", umem_fd, dup_umem_fd2);
	err = send_xsk_fd(sock2, dup_umem_fd2);
	if (err < 0) {
		handle_error("Send dup_umem_fd2 failed");
	}

	// Step 4: load xdp prog
	/*
	err = xsk_setup_xdp_prog(ifindex, &xsks_map_fd);
	if (err) {
		handle_error("Setup of xdp program failed");
	}
	*/

	// Step 5: update xsk map
	xsks_map_fd = bpf_map_get_fd_by_id(opt_map_id); 
	printf("Updating xsk map with queue_id %d, fd %d\n", queue_id, socket_fd1);
	err = update_xsk_map(xsks_map_fd, &queue_id, &socket_fd1);
	if (err) {
		handle_error("Update xsk map failed");
	}
	int alt_queue_id = queue_id + 4;
	printf("Updating xsk map with queue_id %d, fd %d\n", alt_queue_id, socket_fd2);
	err = update_xsk_map(xsks_map_fd, &alt_queue_id, &socket_fd2);
	if (err) {
		handle_error("Update xsk map failed");
	}
	fprintf(stdout, "Updated map with index %d for 1st socket and %d for 2nd socket",
			queue_id, alt_queue_id);


	printf("Setup done!");

	/* Unset fd for given ifindex */
	err = bpf_set_link_xdp_fd(ifindex, -1, 0);
	if (err) {
		fprintf(stderr, "Error when unsetting bpf prog_fd for ifindex(%d)\n", ifindex);
		return err;
	}

	close(sock1);
	close(sock2);
	close(umem_fd);

	while(1){};

	return 0;
}
