// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <linux/if_tun.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <stdbool.h>
#include <pthread.h>
#include <stdarg.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <time.h>

#define CLIENT_NR_MAX_SOCKS	16
#define NR_SERVER_CLIENT_SLOT	4
#define NR_SERVER_TUN_FDS	4
#define SERVER_TUN_NAME		"gws0"
#define CLIENT_TUN_NAME		"gwc0"
#define STR_IP_PORT_LEN		(INET6_ADDRSTRLEN + 16)
#define ARRAY_SIZE(x)		(sizeof(x) / sizeof((x)[0]))
#define GWC_SUBNET		"10.25.0.0/24"
#define GWC_IP_GATEWAY		"10.25.0.1"
#define GWC_IP_CLIENT		"10.25.0.2"
#define GWC_SUBNET_CIDR		24
#define HS_MAGIC		"GWHS"

#ifndef offsetoff
#define offsetoff(type, member)	((size_t)&(((type *)0)->member))
#endif

enum {
	CL_PKT_CLOSE		= 10,
	CL_PKT_HANDSHAKE	= 11,
	CL_PKT_TUN_DATA		= 12,
	CL_PKT_PING		= 13,
	CL_PKT_PING_REPLY	= 14,

	SR_PKT_CLOSE		= 20,
	SR_PKT_HANDSHAKE	= 21,
	SR_PKT_TUN_DATA		= 22,
	SR_PKT_PING		= 23,
	SR_PKT_PING_REPLY	= 24,
};


struct pkt_handshake {
	uint8_t		magic[4];
};

struct pkt {
	uint8_t		type;
	uint8_t		pad;
	__be16		len;
	union {
		struct pkt_handshake	handshake;
		char			__raw[2048];
	};
};

#define PKT_HDR_LEN		(offsetoff(struct pkt, __raw))

struct send_queue;

struct send_queue {
	struct send_queue	*next;
	struct pkt		pkt;
	uint32_t 		len;
	struct sockaddr_storage	dst;
};

struct send_queue_list {
	struct send_queue	*sq_head;
	struct send_queue	*sq_tail;
	struct pollfd		*udp_pfd;
};

struct client_ctx;

struct client_worker {
	bool			handshake_ok;
	bool			need_reconnect;
	bool			need_join;
	int			udp_fd;
	int			tun_fd;
	struct pollfd		pfds[2];
	struct send_queue_list	sql;
	struct client_ctx	*ctx;
	uint32_t		spkt_len;
	uint32_t		cpkt_len;
	struct pkt		spkt;
	struct pkt		cpkt;
	const char		*bind_iface;
	const char		*bind_ip;
	pthread_t		thread;
};

struct client_ctx {
	volatile bool		stop;
	struct sockaddr_storage	dst_addr;
	struct client_worker	*workers;
	uint32_t		nr_workers;

	const char		*server_addr;
	uint16_t		server_port;
};

struct client_slot {
	bool			is_used;
	struct sockaddr_storage	addr;
	struct timespec		last_seen;
};

struct server_ctx {
	volatile bool		stop;
	int			udp_fd;
	int			tun_fds[NR_SERVER_TUN_FDS];
	struct pollfd		*pfds;
	struct client_slot	*clients;
	struct client_slot	*cur_client;
	uint32_t		nr_clients;
	uint32_t		nr_pfds;

	struct sockaddr_storage	addr;

	const char 		*bind_addr;
	uint16_t		bind_port;

	uint32_t		cpkt_len;
	uint32_t		spkt_len;

	struct pkt		cpkt;
	struct pkt		spkt;
	struct send_queue_list	sql;
};

static volatile bool *g_stop_p;

static void signal_handler(int sig)
{
	(void)sig;
	if (g_stop_p)
		*g_stop_p = true;
}

static int install_signal_stop_handler(volatile bool *ptr)
{
	struct sigaction sa = { .sa_handler = signal_handler };
	int ret;

	g_stop_p = ptr;

	printf("Installing signal stop handler...\n");

	ret = sigaction(SIGINT, &sa, NULL);
	if (ret < 0)
		goto out_err;
	ret = sigaction(SIGTERM, &sa, NULL);
	if (ret < 0)
		goto out_err;

	sa.sa_handler = SIG_IGN;
	ret = sigaction(SIGPIPE, &sa, NULL);
	if (ret < 0)
		goto out_err;

	return 0;

out_err:
	ret = errno;
	perror("sigaction()");
	return ret;
}

static int fd_set_nonblock(int fd)
{
	int err, flags;

	flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0) {
		err = errno;
		perror("fcntl(F_GETFL)");
		return -err;
	}

	err = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
	if (err < 0) {
		err = errno;
		perror("fcntl(F_SETFL)");
		return -err;
	}

	return flags;
}

static const char *net_tun_path[] = {
	"/dev/net/tun",
	"/dev/tun",
	NULL,
};

static int open_dev_tun(void)
{
	size_t i;
	int ret;

	for (i = 0; net_tun_path[i] != NULL; i++) {
		ret = open(net_tun_path[i], O_RDWR);
		if (ret >= 0)
			return ret;
	}

	perror("open_dev_tun()");
	return ret;
}

/*
 * https://www.kernel.org/doc/Documentation/networking/tuntap.txt
 *
 * Flags: IFF_TUN   - TUN device (no Ethernet headers)
 *        IFF_TAP   - TAP device
 *
 *        IFF_NO_PI - Do not provide packet information
 *        IFF_MULTI_QUEUE - Create a queue of multiqueue device
 */
static int tun_alloc(const char *dev, short flags)
{
	struct ifreq ifr;
	int fd, err;

	if (dev == NULL || dev[0] == '\0') {
		printf("tun_alloc(): dev cannot be empty\n");
		return -EINVAL;
	}

	fd = open_dev_tun();
	if (fd < 0)
		return fd;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
	ifr.ifr_name[IFNAMSIZ - 1] = '\0';
	ifr.ifr_flags = flags;

	if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
		err = errno;
		close(fd);
		printf("ioctl(%d, TUNSETIFF, &ifr): %s\n", fd, strerror(err));
		return -err;
	}

	return fd;
}

static int str_to_sockaddr(struct sockaddr_storage *ss, const char *addr,
			   uint16_t port)
{
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ss;
	struct sockaddr_in *sin = (struct sockaddr_in *)ss;
	int ret;

	ret = inet_pton(AF_INET6, addr, &sin6->sin6_addr);
	if (ret == 1) {
		sin6->sin6_family = AF_INET6;
		sin6->sin6_port = htons(port);
		return 0;
	}

	ret = inet_pton(AF_INET, addr, &sin->sin_addr);
	if (ret == 1) {
		sin->sin_family = AF_INET;
		sin->sin_port = htons(port);
		return 0;
	}

	return -EINVAL;
}

static int sockaddr_to_str(char *addr, const struct sockaddr_storage *ss)
{
	int family = ss->ss_family;
	const void *raw_addr;
	uint16_t port;

	if (family != AF_INET && family != AF_INET6)
		return -EINVAL;

	if (family == AF_INET6) {
		struct sockaddr_in6 *in6 = (void *)ss;
		*addr++ = '[';
		port = in6->sin6_port;
		raw_addr = &in6->sin6_addr;
	} else {
		struct sockaddr_in *in = (void *)ss;
		port = in->sin_port;
		raw_addr = &in->sin_addr;
	}

	if (!inet_ntop(family, raw_addr, addr, INET6_ADDRSTRLEN))
		return -errno;

	addr += strlen(addr);
	if (family == AF_INET6)
		*addr++ = ']';

	*addr++ = ':';
	sprintf(addr, "%hu", ntohs(port));
	return 0;
}

static char *addr_to_str_pt(const struct sockaddr_storage *ss)
{
	static __thread char __buf[8][STR_IP_PORT_LEN];
	static __thread uint8_t __idx = 0;
	char *buf;
	
	buf = __buf[__idx++ % ARRAY_SIZE(__buf)];
	if (sockaddr_to_str(buf, ss) < 0)
		return "(invalid_addr)";

	return buf;
}

static socklen_t get_sockaddr_len(const struct sockaddr_storage *ss)
{
	switch (ss->ss_family) {
	case AF_INET:
		return sizeof(struct sockaddr_in);
	case AF_INET6:
		return sizeof(struct sockaddr_in6);
	default:
		return 0;
	}
}

static int create_udp_sock_and_bind(int family, struct sockaddr_storage *ss)
{
	int fd, err, tmp;

	fd = socket(family, SOCK_DGRAM | SOCK_NONBLOCK, 0);
	if (fd < 0) {
		err = errno;
		perror("socket(AF_INET6, SOCK_DGRAM, 0)");
		return -err;
	}

	tmp = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &tmp, sizeof(tmp));

	tmp = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &tmp, sizeof(tmp));

	tmp = 1024 * 1024 * 128;
	setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &tmp, sizeof(tmp));

	tmp = 1024 * 1024 * 128;
	setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &tmp, sizeof(tmp));

	err = bind(fd, (struct sockaddr *)ss, get_sockaddr_len(ss));
	if (err < 0) {
		err = errno;
		perror("bind()");
		close(fd);
		return -err;
	}

	return fd;
}

static int server_init_tun_fds(struct server_ctx *ctx)
{
	const short flags = IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE;
	int i, ret, fd;

	for (i = 0; i < NR_SERVER_TUN_FDS; i++) {
		ret = tun_alloc(SERVER_TUN_NAME, flags);
		if (ret < 0)
			goto out_err;
		
		fd = ret;
		ret = fd_set_nonblock(fd);
		if (ret < 0) {
			close(fd);
			goto out_err;
		}

		printf("Allocated TUN device (fd=%d)\n", fd);
		ctx->tun_fds[i] = fd;
	}

	return 0;

out_err:

	for (i--; i >= 0; i--)
		close(ctx->tun_fds[i]);

	for (i = 0; i < NR_SERVER_TUN_FDS; i++)
		ctx->tun_fds[i] = -1;

	return ret;
}

static int pr_exec(const char *fmt, ...)
{
	char buf[8192];
	va_list ap;
	int ret;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	printf("!! Executing: %s\n", buf);
	ret = system(buf);
	if (ret != 0)
		printf("Execution failed!\n");

	return ret;
}

static int server_bring_up_iface(struct server_ctx *ctx)
{
	int ret = 0;

	ret |= pr_exec("ip link set dev %s up", SERVER_TUN_NAME);
	ret |= pr_exec("ip addr add %s/%d dev %s", GWC_IP_GATEWAY, GWC_SUBNET_CIDR, SERVER_TUN_NAME);

	(void)ctx;
	return ret;
}

static int server_get_bind_info(struct server_ctx *ctx,
				struct sockaddr_storage *ss)
{
	char *tmp;
	int ret;

	ctx->bind_addr = "::";
	ctx->bind_port = 60443;

	tmp = getenv("GWC_BIND_ADDR");
	if (tmp)
		ctx->bind_addr = tmp;

	tmp = getenv("GWC_BIND_PORT");
	if (tmp)
		ctx->bind_port = (uint16_t)atoi(tmp);

	ret = str_to_sockaddr(ss, ctx->bind_addr, ctx->bind_port);
	if (ret < 0) {
		printf("Invalid bind address: %s\n", ctx->bind_addr);
		return -EINVAL;
	}

	return 0;
}

static int server_init_udp_sock(struct server_ctx *ctx)
{
	struct sockaddr_storage ss;
	int ret;

	ret = server_get_bind_info(ctx, &ss);
	if (ret < 0)
		return ret;

	ret = create_udp_sock_and_bind(ss.ss_family, &ss);
	if (ret < 0)
		return ret;

	printf("Created UDP socket (fd=%d)\n", ret);
	printf("Binding UDP socket to %s...\n", addr_to_str_pt(&ss));
	ctx->udp_fd = ret;
	return 0;
}

static int server_init_poll_fds(struct server_ctx *ctx)
{
	uint32_t nr_pfds = 1 + NR_SERVER_TUN_FDS;
	struct pollfd *fds;
	uint32_t i;

	fds = calloc(nr_pfds, sizeof(*fds));
	if (!fds) {
		printf("Cannot allocate memory for pollfds\n");
		return -ENOMEM;
	}

	fds[0].fd = ctx->udp_fd;
	fds[0].events = POLLIN | POLLPRI;
	fds[0].revents = 0;

	for (i = 0; i < NR_SERVER_TUN_FDS; i++) {
		fds[i + 1].fd = ctx->tun_fds[i];
		fds[i + 1].events = POLLIN | POLLPRI;
		fds[i + 1].revents = 0;
	}

	ctx->pfds = fds;
	ctx->nr_pfds = nr_pfds;
	ctx->sql.udp_pfd = &ctx->pfds[0];
	return 0;
}

static int server_init_client_slots(struct server_ctx *ctx)
{
	struct client_slot *slots;

	slots = calloc(NR_SERVER_CLIENT_SLOT, sizeof(*slots));
	if (!slots) {
		printf("Cannot allocate memory for client slots\n");
		return -ENOMEM;
	}

	ctx->clients = slots;
	ctx->nr_clients = NR_SERVER_CLIENT_SLOT;
	return 0;
}

static int server_poll_events(struct server_ctx *ctx)
{
	int ret;

	ret = poll(ctx->pfds, ctx->nr_pfds, 1000);
	if (ret < 0) {
		ret = errno;

		if (ret == EINTR)
			return 0;

		perror("poll()");
		return -ret;
	}

	return ret;
}

static struct client_slot *server_lookup_client(struct server_ctx *ctx,
						struct sockaddr_storage *ss)
{
	struct client_slot *ret;
	size_t i;

	for (i = 0; i < ctx->nr_clients; i++) {
		ret = &ctx->clients[i];
		if (!ret->is_used)
			continue;
		if (memcmp(&ret->addr, ss, sizeof(*ss)) == 0)
			return ret;
	}

	return NULL;
}

static struct client_slot *server_get_client_slot(struct server_ctx *ctx)
{
	struct client_slot *ret;
	size_t i;

	for (i = 0; i < ctx->nr_clients; i++) {
		ret = &ctx->clients[i];
		if (!ret->is_used) {
			ret->is_used = true;
			return ret;
		}
	}

	return NULL;
}

static ssize_t __queue_sendto(struct send_queue_list *sql, struct pkt *pkt,
			      uint32_t len, struct sockaddr_storage *ss)
{
	struct send_queue *head = sql->sq_head;
	struct send_queue *tail = sql->sq_tail;
	struct send_queue *sq;

	sq = malloc(sizeof(*sq));
	if (!sq) {
		printf("Cannot allocate memory for send queue\n");
		return -ENOMEM;
	}

	sql->udp_pfd->events |= POLLOUT;
	sq->dst = *ss;
	sq->len = len;
	sq->pkt = *pkt;
	sq->next = NULL;

	if (!tail) {
		assert(!head);
		sql->sq_head = sql->sq_tail = sq;
		return (ssize_t)len;
	}

	assert(head);
	assert(tail);

	tail->next = sq;
	sql->sq_tail = sq;
	return 0;
}

static int queue_sendto(struct send_queue_list *sql, struct pkt *pkt,
			uint32_t len, struct sockaddr_storage *ss)
{
	socklen_t ss_len = get_sockaddr_len(ss);
	int fd = sql->udp_pfd->fd;
	ssize_t ret;

	ret = sendto(fd, pkt, len, MSG_DONTWAIT, (struct sockaddr *)ss, ss_len);
	if (ret < 0) {

		ret = errno;
		if (ret == EAGAIN)
			return (int)__queue_sendto(sql, pkt, len, ss);

		perror("sendto()");
		return -ret;
	}

	return (int)ret;
}

static int server_respond_handshake(struct server_ctx *ctx)
{
	struct client_slot *client = ctx->cur_client;
	uint32_t len;
	ssize_t ret;

	ctx->spkt.type = SR_PKT_HANDSHAKE;
	ctx->spkt.pad = 0;
	ctx->spkt.len = htons(sizeof(ctx->spkt.handshake));
	memcpy(ctx->spkt.handshake.magic, HS_MAGIC, sizeof(HS_MAGIC));

	len = PKT_HDR_LEN + sizeof(ctx->spkt.handshake);
	ret = queue_sendto(&ctx->sql, &ctx->spkt, len, &client->addr);
	if (ret < 0)
		return ret;

	return 0;
}

static int server_handle_client_pkt_handshake(struct server_ctx *ctx)
{
	struct pkt_handshake *hs = &ctx->cpkt.handshake;
	struct client_slot *client;
	int ret;

	if (ctx->cpkt_len != PKT_HDR_LEN + sizeof(*hs)) {
		printf("Invalid handshake packet length: %u from %s\n",
		       ctx->cpkt_len, addr_to_str_pt(&ctx->addr));
		return 0;
	}

	if (memcmp(hs->magic, HS_MAGIC, sizeof(hs->magic)) != 0) {
		printf("Invalid handshake magic (%u, %u, %u, %u) from %s\n",
		       hs->magic[0], hs->magic[1], hs->magic[2], hs->magic[3],
		       addr_to_str_pt(&ctx->addr));
		return 0;
	}

	if (ctx->cur_client) {
		printf("Client %s sent a duplicate handshake packet\n",
		       addr_to_str_pt(&ctx->addr));
		return 0;
	}

	client = server_get_client_slot(ctx);
	if (!client) {
		printf("No more client slot available\n");
		return 0;
	}

	client->addr = ctx->addr;
	ctx->cur_client = client;
	ret = server_respond_handshake(ctx);
	if (ret < 0) {
		client->is_used = false;
		return ret;
	}

	printf("Accepted a new client: %s\n", addr_to_str_pt(&ctx->addr));
	return ret;
}

static int server_handle_client_pkt_ping(struct server_ctx *ctx)
{
	if (!ctx->cur_client)
		return 0;

	return 0;
}

static int server_handle_client_pkt_tun_data(struct server_ctx *ctx)
{
	struct client_slot *client = ctx->cur_client;
	struct pkt *pkt = &ctx->cpkt;
	ssize_t ret;

	if (!client)
		return 0;

	pkt->len = ntohs(pkt->len);
	if (ctx->cpkt_len != PKT_HDR_LEN + pkt->len) {
		printf("Invalid TUN data packet length: %u from %s\n",
		       ctx->cpkt_len, addr_to_str_pt(&ctx->addr));
		return 0;
	}

	ret = write(ctx->tun_fds[0], pkt->__raw, pkt->len);
	if (ret < 0) {
		ret = errno;
		if (ret == EAGAIN)
			return 0;

		perror("write()");
		return -ret;
	}

	return 0;
}

static int server_handle_client_packet(struct server_ctx *ctx)
{
	uint16_t len;
	int ret;

	if (ctx->cpkt_len < offsetoff(struct pkt, __raw)) {
		printf("Client %s sent an invalid packet length: %u\n",
		       addr_to_str_pt(&ctx->addr), ctx->cpkt_len);
		return 0;
	}

	len = ntohs(ctx->cpkt.len);
	if (ctx->cpkt_len != offsetoff(struct pkt, __raw) + len) {
		printf("Client %s sent an invalid packet length: %u\n",
		       addr_to_str_pt(&ctx->addr), ctx->cpkt_len);
		return 0;
	}

	ctx->cur_client = server_lookup_client(ctx, &ctx->addr);
	switch (ctx->cpkt.type) {
	case CL_PKT_HANDSHAKE:
		ret = server_handle_client_pkt_handshake(ctx);
		break;
	case CL_PKT_PING:
		ret = server_handle_client_pkt_ping(ctx);
		break;
	case CL_PKT_TUN_DATA:
		ret = server_handle_client_pkt_tun_data(ctx);
		break;
	default:
		if (ctx->cur_client) {
			printf("Client %s sent an invalid packet type: %u\n",
			       addr_to_str_pt(&ctx->addr), ctx->cpkt.type);
		}

		ret = 0;
		break;
	}

	return ret;
}

static int server_handle_udp_packet(struct server_ctx *ctx)
{
	struct sockaddr *sa;
	socklen_t sa_len;
	ssize_t ret;
	size_t len;
	void *buf;

	memset(&ctx->addr, 0, sizeof(ctx->addr));

	sa = (void *)&ctx->addr;
	sa_len = sizeof(ctx->addr);

	buf = &ctx->cpkt;
	len = sizeof(ctx->cpkt);
	ret = recvfrom(ctx->udp_fd, buf, len, MSG_DONTWAIT, sa, &sa_len);
	if (ret < 0) {
		ret = errno;
		if (ret == EAGAIN)
			return 0;

		perror("recvfrom()");
		return -ret;
	}

	if (sa_len > sizeof(ctx->addr)) {
		printf("recvfrom(): Invalid sockaddr length: %u\n", (unsigned)sa_len);
		return -EINVAL;
	}

	if (ret == 0) {
		printf("recvfrom(): UDP connection is closed, zero returned\n");
		return -ENETDOWN;
	}

	ctx->cpkt_len = (uint32_t)ret;
	return server_handle_client_packet(ctx);
}

static struct client_slot *server_find_active_client(struct server_ctx *ctx)
{
	struct client_slot *clients = ctx->clients;
	uint32_t i;

	for (i = 0; i < ctx->nr_clients; i++) {
		if (!clients[i].is_used)
			continue;

		return &clients[i];
	}

	return NULL;
}

static int server_handle_tun_packet(struct server_ctx *ctx, int fd)
{
	struct pkt *pkt = &ctx->spkt;
	struct client_slot *client;
	ssize_t ret;

	ret = read(fd, pkt->__raw, sizeof(pkt->__raw));
	if (ret < 0) {
		ret = errno;
		if (ret == EAGAIN)
			return 0;

		perror("read()");
		return -ret;
	}

	client = server_find_active_client(ctx);
	if (!client)
		return 0;

	pkt->type = SR_PKT_TUN_DATA;
	pkt->pad = 0;
	pkt->len = htons((uint16_t)ret);

	ret = queue_sendto(&ctx->sql, pkt, PKT_HDR_LEN + ret, &client->addr);
	if (ret < 0)
		return ret;

	return 0;
}

static int server_handle_events(struct server_ctx *ctx, int nr_events)
{
	uint32_t nr = (uint32_t)nr_events;
	uint32_t i;
	int ret = 0;

	if (ctx->pfds[0].revents & POLLIN) {
		ret = server_handle_udp_packet(ctx);
		if (ret < 0)
			return ret;

		nr--;
	}

	for (i = 0; i < NR_SERVER_TUN_FDS; i++) {
		if (nr == 0)
			break;

		if (!(ctx->pfds[i + 1].revents & POLLIN))
			continue;

		ret = server_handle_tun_packet(ctx, ctx->pfds[i + 1].fd);
		if (ret < 0)
			return ret;
	}

	return ret;
}

static int server_run_event_loop(struct server_ctx *ctx)
{
	int ret = 0;

	printf("Server is ready!\n");
	while (!ctx->stop) {
		ret = server_poll_events(ctx);
		if (ret < 0)
			break;

		ret = server_handle_events(ctx, ret);
		if (ret < 0)
			break;
	}

	return ret;
}

static void server_destroy_ctx(struct server_ctx *ctx)
{
	uint32_t i;

	for (i = 0; i < NR_SERVER_TUN_FDS; i++)
		close(ctx->tun_fds[i]);

	if (ctx->udp_fd >= 0)
		close(ctx->udp_fd);

	free(ctx->pfds);
	free(ctx->clients);
}

static int run_server(void)
{
	struct server_ctx ctx;
	int ret;

	memset(&ctx, 0, sizeof(ctx));
	ctx.udp_fd = -1;

	ret = server_init_tun_fds(&ctx);
	if (ret < 0)
		return ret;

	ret = server_bring_up_iface(&ctx);
	if (ret < 0)
		goto out;

	ret = server_init_udp_sock(&ctx);
	if (ret < 0)
		goto out;

	ret = server_init_poll_fds(&ctx);
	if (ret < 0)
		goto out;

	ret = server_init_client_slots(&ctx);
	if (ret < 0)
		goto out;

	ret = install_signal_stop_handler(&ctx.stop);
	if (ret < 0)
		goto out;

	ret = server_run_event_loop(&ctx);

out:
	server_destroy_ctx(&ctx);
	return abs(ret);
}

static const char *getenv_fmt(const char *fmt, ...)
{
	char buf[512];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	return getenv(buf);
}

static int client_init_worker(struct client_ctx *ctx, uint32_t i,
			      const char *iface, const char *ip)
{
	struct client_worker *worker = &ctx->workers[i];
	struct sockaddr_storage bind_ip;
	int err, udp_fd, tun_fd;

	worker->udp_fd = -1;
	worker->tun_fd = -1;

	if (str_to_sockaddr(&bind_ip, ip, 0)) {
		printf("Invalid GWC_BIND_IP_%03u: %s\n", i, ip);
		return -EINVAL;
	}

	udp_fd = create_udp_sock_and_bind(bind_ip.ss_family, &bind_ip);
	if (udp_fd < 0)
		return udp_fd;

	err = setsockopt(udp_fd, SOL_SOCKET, SO_BINDTODEVICE, iface, strlen(iface) + 1);
	if (err < 0) {
		err = errno;
		printf("Error while binding interface GWC_BIND_IFACE_%03u: %s\n",
		       i, iface);
		perror("setsockopt(SO_BINDTODEVICE)");
		close(udp_fd);
		return -err;
	}

	printf("Created UDP socket (fd=%d) for %s (%s)\n", udp_fd, iface, ip);
	err = connect(udp_fd, (struct sockaddr *)&ctx->dst_addr, get_sockaddr_len(&ctx->dst_addr));
	if (err < 0) {
		err = errno;
		printf("Error while connecting to server: %s\n", ctx->server_addr);
		perror("connect()");
		close(udp_fd);
		return -err;
	}

	tun_fd = tun_alloc(CLIENT_TUN_NAME, IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE);
	if (tun_fd < 0) {
		close(udp_fd);
		return tun_fd;
	}

	err = fd_set_nonblock(tun_fd);
	if (err < 0) {
		close(udp_fd);
		close(tun_fd);
		return err;
	}

	printf("Allocated TUN device (fd=%d) for %s (%s)\n", tun_fd, iface, ip);

	worker->udp_fd = udp_fd;
	worker->tun_fd = tun_fd;
	worker->bind_iface = iface;
	worker->bind_ip = ip;
	worker->pfds[0].fd = udp_fd;
	worker->pfds[0].events = POLLIN | POLLPRI;
	worker->pfds[0].revents = 0;
	worker->pfds[1].fd = tun_fd;
	worker->pfds[1].events = POLLIN | POLLPRI;
	worker->pfds[1].revents = 0;
	return 0;
}

static int client_interpret_env_it(struct client_ctx *ctx, uint32_t i)
{
	struct client_worker *workers;
	const char *tmp, *iface, *ip;

	tmp = getenv_fmt("GWC_BIND_IFACE_%03u", i);
	if (!tmp)
		return -9999;

	iface = tmp;

	tmp = getenv_fmt("GWC_BIND_IP_%03u", i);
	if (!tmp)
		return -9999;

	ip = tmp;

	workers = realloc(ctx->workers, (i + 1) * sizeof(*workers));
	if (!workers) {
		printf("Cannot allocate memory for workers (i = %u)\n", i);
		return -ENOMEM;
	}

	memset(&workers[i], 0, sizeof(*workers));
	ctx->workers = workers;
	ctx->nr_workers = i + 1;
	return client_init_worker(ctx, i, iface, ip);
}

static int client_interpret_env(struct client_ctx *ctx)
{
	uint32_t i, nr = 0;
	const char *tmp;
	int ret;

	tmp = getenv("GWC_SERVER_ADDR");
	if (!tmp)
		goto out_err;

	ctx->server_addr = tmp;

	tmp = getenv("GWC_SERVER_PORT");
	if (!tmp)
		goto out_err;

	ctx->server_port = (uint16_t)atoi(tmp);

	if (!ctx->server_port) {
		printf("Invalid server port: %s\n", tmp);
		return -EINVAL;
	}

	if (str_to_sockaddr(&ctx->dst_addr, ctx->server_addr, ctx->server_port)) {
		printf("Invalid server address: %s\n", ctx->server_addr);
		return -EINVAL;
	}

	printf("Destination server is %s\n", addr_to_str_pt(&ctx->dst_addr));
	for (i = 0; i < CLIENT_NR_MAX_SOCKS; i++) {
		ret = client_interpret_env_it(ctx, i);
		if (ret == -9999)
			break;

		nr++;
		if (ret < 0)
			break;
	}

	if (nr == 0)
		goto out_err;

	if (ret == -9999)
		ret = 0;

	return ret;

out_err:
	printf("Incomplete environment variables!\n");
	printf("Required environment variables:\n");
	printf("  GWC_SERVER_ADDR\n");
	printf("  GWC_SERVER_PORT\n");
	printf("  GWC_BIND_IFACE_000\n");
	printf("  GWC_BIND_IP_000\n");
	return -EINVAL;
}

static int client_bring_up_iface(struct client_ctx *ctx)
{
	int ret = 0;

	ret |= pr_exec("ip link set dev %s up", CLIENT_TUN_NAME);
	ret |= pr_exec("ip addr add %s/%d dev %s", GWC_IP_GATEWAY, GWC_SUBNET_CIDR, CLIENT_TUN_NAME);

	(void)ctx;
	return ret;
}

static int client_perform_handshake(struct client_worker *wrk)
{
	struct client_ctx *ctx = wrk->ctx;
	uint32_t len;
	int ret;

	wrk->cpkt.type = CL_PKT_HANDSHAKE;
	wrk->cpkt.pad = 0;
	wrk->cpkt.len = htons(sizeof(wrk->cpkt.handshake));
	memcpy(wrk->cpkt.handshake.magic, HS_MAGIC, sizeof(HS_MAGIC));

	len = PKT_HDR_LEN + sizeof(wrk->cpkt.handshake);
	ret = queue_sendto(&wrk->sql, &wrk->cpkt, len, &ctx->dst_addr);
	if (ret <= 0) {

		if (ret == 0 && wrk->handshake_ok) {
			assert(wrk->need_reconnect);
			return 0;
		}

		printf("Cannot send handshake packet to server\n");
		ctx->stop = true;
		return ret;
	}

	return 0;
}

static int client_poll_events(struct client_worker *wrk)
{
	int ret;

	ret = poll(wrk->pfds, 2, 1000);
	if (ret < 0) {
		ret = errno;
		if (ret == EINTR)
			return 0;

		perror("poll()");
		return -ret;
	}

	return ret;
}

static int client_handle_server_handshake(struct client_worker *wrk)
{
	struct pkt_handshake *hs = &wrk->spkt.handshake;

	if (wrk->cpkt_len != PKT_HDR_LEN + sizeof(*hs)) {
		printf("Invalid handshake packet length: %u\n", wrk->cpkt_len);
		return 0;
	}

	if (memcmp(hs->magic, HS_MAGIC, sizeof(hs->magic)) != 0) {
		printf("Invalid handshake magic (%u, %u, %u, %u)\n",
		       hs->magic[0], hs->magic[1], hs->magic[2], hs->magic[3]);
		return 0;
	}

	printf("%s (%s) is connected to the server\n", wrk->bind_iface, wrk->bind_ip);
	wrk->handshake_ok = true;
	return 0;
}

static int client_handle_server_tun_data(struct client_worker *wrk)
{
	uint32_t len;
	ssize_t ret;

	if (!wrk->handshake_ok) {
		printf("Received a TUN packet with handshake_ok equals to false\n");
		return 0;
	}

	len = ntohs(wrk->spkt.len);
	if (wrk->cpkt_len != PKT_HDR_LEN + len) {
		printf("Invalid server TUN packet length: %u (expected len = %u)\n", len, wrk->cpkt_len);
		return 0;
	}

	ret = write(wrk->tun_fd, wrk->spkt.__raw, len);
	if (ret < 0) {
		ret = errno;
		if (ret == EAGAIN)
			return 0;

		perror("write()");
		return -ret;
	}

	return 0;
}

static int __client_handle_udp_packet(struct client_worker *wrk)
{
	struct pkt *pkt = &wrk->spkt;
	uint16_t len;
	int ret = 0;

	if (wrk->cpkt_len < offsetoff(struct pkt, __raw)) {
		printf("Corrupted packet length: %u (smaller than packet header)\n", wrk->cpkt_len);
		return 0;
	}

	len = ntohs(pkt->len);
	if (wrk->cpkt_len < offsetoff(struct pkt, __raw) + len) {
		printf("Corrupted packet length: %u (expected len = %u)\n", len, wrk->cpkt_len);
		return 0;
	}

	switch (pkt->type) {
	case SR_PKT_HANDSHAKE:
		ret = client_handle_server_handshake(wrk);
		break;
	case SR_PKT_PING:
		break;
	case SR_PKT_TUN_DATA:
		ret = client_handle_server_tun_data(wrk);
		break;
	default:
		printf("Received an invalid packet type: %u (len = %u)\n", pkt->type, len);
		ret = 0;
		break;
	}

	return ret;
}

static int client_handle_udp_packet(struct client_worker *wrk)
{
	ssize_t ret;

	ret = recv(wrk->udp_fd, &wrk->spkt, sizeof(wrk->spkt), MSG_DONTWAIT);
	if (ret < 0) {
		ret = errno;
		if (ret == EAGAIN)
			return 0;

		perror("recv()");
		return -ret;
	}

	if (ret == 0) {
		printf("recv(): UDP connection is closed, zero returned\n");
		return -ENETDOWN;
	}

	wrk->cpkt_len = (uint32_t)ret;
	return __client_handle_udp_packet(wrk);
}

static int client_handle_tun_packet(struct client_worker *wrk)
{
	struct client_ctx *ctx = wrk->ctx;
	uint32_t len;
	ssize_t ret;

	ret = read(wrk->tun_fd, wrk->cpkt.__raw, sizeof(wrk->cpkt.__raw));
	if (ret < 0) {
		ret = errno;
		if (ret == EAGAIN)
			return 0;

		perror("read()");
		return -ret;
	}

	printf("Read %zd bytes from TUN device\n", ret);

	len = (uint32_t)ret;
	wrk->cpkt.type = CL_PKT_TUN_DATA;
	wrk->cpkt.pad = 0;
	wrk->cpkt.len = htons((uint16_t)len);
	len = PKT_HDR_LEN + len;
	return queue_sendto(&wrk->sql, &wrk->cpkt, len, &ctx->dst_addr);
}

static int client_handle_events(struct client_worker *wrk, int nr_events)
{
	uint32_t nr = (uint32_t)nr_events;
	int ret = 0;

	if (wrk->pfds[0].revents & POLLIN) {
		ret = client_handle_udp_packet(wrk);
		if (ret < 0)
			return ret;

		nr--;
	}

	if (nr && wrk->pfds[1].revents & POLLIN) {
		ret = client_handle_tun_packet(wrk);
		if (ret < 0)
			return ret;
	}

	return ret;
}

static void *client_run_event_loop(void *arg)
{
	struct client_worker *wrk = arg;
	struct client_ctx *ctx = wrk->ctx;
	int ret = 0;

	assert(ctx);

	printf("Worker for %s (%s) is ready!\n", wrk->bind_iface, wrk->bind_ip);

	wrk->sql.udp_pfd = &wrk->pfds[0];
	ret = client_perform_handshake(wrk);
	if (ret < 0)
		goto out;

	while (!ctx->stop) {
		ret = client_poll_events(wrk);
		if (ret < 0)
			break;

		ret = client_handle_events(wrk, ret);
		if (ret < 0)
			break;
	}

out:
	return (void *)((intptr_t)(ret));
}

static int client_start_worker(struct client_ctx *ctx, uint32_t i)
{
	struct client_worker *wrk = &ctx->workers[i];
	int ret;

	if (i == 0)
		return 0;

	ret = pthread_create(&wrk->thread, NULL, client_run_event_loop, wrk);
	if (ret < 0) {
		ret = errno;
		perror("pthread_create()");
		return -ret;
	}

	ctx->workers[i].need_join = true;
	return 0;
}

static int client_start_workers(struct client_ctx *ctx)
{
	uint32_t i;

	for (i = 0; i < ctx->nr_workers; i++) {
		int ret;

		ctx->workers[i].ctx = ctx;
		ret = client_start_worker(ctx, i);
		if (ret < 0)
			return ret;
	}

	return 0;
}

static void client_destroy_ctx(struct client_ctx *ctx)
{
	uint32_t i;

	for (i = 0; i < ctx->nr_workers; i++) {
		if (i > 0 && ctx->workers[i].need_join)
			pthread_kill(ctx->workers[i].thread, SIGTERM);
	}

	for (i = 0; i < ctx->nr_workers; i++) {
		if (i > 0 && ctx->workers[i].need_join)
			pthread_join(ctx->workers[i].thread, NULL);
		if (ctx->workers[i].udp_fd >= 0)
			close(ctx->workers[i].udp_fd);
		if (ctx->workers[i].tun_fd >= 0)
			close(ctx->workers[i].tun_fd);
	}

	free(ctx->workers);
}

static int run_client(void)
{
	struct client_ctx ctx;
	int ret;

	memset(&ctx, 0, sizeof(ctx));

	ret = client_interpret_env(&ctx);
	if (ret < 0)
		return ret;

	ret = client_bring_up_iface(&ctx);
	if (ret < 0)
		goto out;

	ret = install_signal_stop_handler(&ctx.stop);
	if (ret < 0)
		goto out;

	ret = client_start_workers(&ctx);
	if (ret < 0)
		goto out;

	ret = (int)((intptr_t)client_run_event_loop(&ctx.workers[0]));

out:
	client_destroy_ctx(&ctx);
	return abs(ret);
}

int main(int argc, char *argv[])
{
	if (argc < 2) {
		printf("Usage: %s [server|client]\n", argv[0]);
		return 1;
	}

	if (strcmp(argv[1], "server") == 0)
		return run_server();
	else if (strcmp(argv[1], "client") == 0)
		return run_client();

	printf("Usage: %s [server|client]\n", argv[0]);
	return 1;
}
