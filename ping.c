/*
 * Copyright (c) 1989 The Regents of the University of California.
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Mike Muuss.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*
 *			P I N G . C
 *
 * Using the InterNet Control Message Protocol (ICMP) "ECHO" facility,
 * measure round-trip-delays and packet loss across network paths.
 *
 * Author -
 *	Mike Muuss
 *	U. S. Army Ballistic Research Laboratory
 *	December, 1983
 *
 * Status -
 *	Public Domain.  Distribution Unlimited.
 * Bugs -
 *	More statistics could always be gathered.
 *	If kernel does not support non-raw ICMP sockets,
 *	this program has to run SUID to ROOT or with
 *	net_cap_raw enabled.
 */

#include "ping.h"

#include <assert.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#ifndef WITHOUT_IFADDRS
#include <ifaddrs.h>
#endif

#ifndef ICMP_FILTER
#define ICMP_FILTER	1
struct icmp_filter {
	__u32	data;
};
#endif

#define	MAXIPLEN	60
#define	MAXICMPLEN	76
#define	NROUTES		9		/* number of record route slots */
#define TOS_MAX		255		/* 8-bit TOS field */

static void pr_options(unsigned char * cp, int hlen, struct gbl_data *data);
static void pr_iph(struct iphdr *ip, struct gbl_data *data);
static unsigned short in_cksum(const unsigned short *addr, int len, unsigned short salt);
static void pr_icmph(__u8 type, __u8 code, __u32 info, struct icmphdr *icp, struct gbl_data *data);

char *pr_addr(void *sa, socklen_t salen, struct gbl_data *data);

extern int ping4_send_probe(socket_st *, void *packet, unsigned packet_size, struct gbl_data *data);
extern int ping4_receive_error_msg(socket_st *, struct gbl_data *);
extern int ping4_parse_reply(socket_st *, struct msghdr *msg, int len, void *addr, struct timeval *, struct gbl_data *);
extern void ping4_install_filter(socket_st *, struct gbl_data *);
extern void sock_setbufs(socket_st*, int alloc, struct gbl_data *data);
extern int setup(socket_st *, struct gbl_data *);
extern int contains_pattern_in_payload(__u8 *ptr, struct gbl_data *data);
extern int main_loop(ping_func_set_st *fset, socket_st*, __u8 *buf, int buflen, struct gbl_data *data);
extern int gather_statistics(__u8 *ptr, int icmplen,
			     int cc, __u16 seq, int hops,
			     int csfailed, struct timeval *tv, char *from,
			     void (*pr_reply)(__u8 *ptr, int cc), struct gbl_data *data);
extern void print_timestamp(struct gbl_data *data);

extern int limit_capabilities(struct gbl_data *data);
extern int modify_capability(int, struct gbl_data *);

static inline int enable_capability_raw(struct gbl_data *dt)		{ return modify_capability(1, dt); };
static inline int disable_capability_raw(struct gbl_data *dt)		{ return modify_capability(0, dt); };

inline int is_ours(socket_st *sock, uint16_t id, struct gbl_data *data) {
       return sock->socktype == SOCK_DGRAM || id == data->ident;
}

struct gbl_data data = {.interval = 1000, .preload = 1, .lingertime = 1000, .confirm = 0, .npackets = 1, .broadcast_pings = 0, .source.sin_family = AF_INET,
			.pmtudisc = -1, .in_pr_addr = 0, .tmin = LONG_MAX, .confirm_flag = MSG_CONFIRM, .screen_width = INT_MAX, .blocking = 0};

static int create_socket(socket_st *sock, int family, int socktype, int protocol, int requisite, struct gbl_data *data)
{
	int do_fallback = 0;

	errno = 0;

	assert(sock->fd == -1);
	assert(socktype == SOCK_DGRAM || socktype == SOCK_RAW);

	/* Attempt to create a ping socket if requested. Attempt to create a raw
	 * socket otherwise or as a fallback. Well known errno values follow.
	 *
	 * 1) EACCES
	 *
	 * Kernel returns EACCES for all ping socket creation attempts when the
	 * user isn't allowed to use ping socket. A range of group ids is
	 * configured using the `net.ipv4.ping_group_range` sysctl. Fallback
	 * to raw socket is necessary.
	 *
	 * Kernel returns EACCES for all raw socket creation attempts when the
	 * proces doesn't have the `CAP_NET_RAW` capability.
	 *
	 * 2) EAFNOSUPPORT
	 *
	 * Kernel returns EAFNOSUPPORT for IPv6 ping or raw socket creation
	 * attempts when run with IPv6 support disabled (e.g. via `ipv6.disable=1`
	 * kernel command-line option.
	 *
	 * https://github.com/iputils/iputils/issues/32
	 *
	 * OpenVZ 2.6.32-042stab113.11 and possibly other older kernels return
	 * EAFNOSUPPORT for all IPv4 ping socket creation attempts due to lack
	 * of support in the kernel. Fallback to raw socket is necessary.
	 *
	 * https://github.com/iputils/iputils/issues/54
	 *
	 * 3) EPROTONOSUPPORT
	 *
	 * OpenVZ 2.6.32-042stab113.11 and possibly other older kernels return
	 * EPROTONOSUPPORT for all IPv6 ping socket creation attempts due to lack
	 * of support in the kernel. Fallback to raw socket is necessary.
	 *
	 * https://github.com/iputils/iputils/issues/54
	 *
	 */
	if (socktype == SOCK_DGRAM)
		sock->fd = socket(family, socktype, protocol);

	/* Kernel doesn't support ping sockets. */
	if (sock->fd == -1 && errno == EAFNOSUPPORT && family == AF_INET)
		do_fallback = 1;
	if (sock->fd == -1 && errno == EPROTONOSUPPORT && family == AF_INET6)
		do_fallback = 1;

	/* User is not allowed to use ping sockets. */
	if (sock->fd == -1 && errno == EACCES)
		do_fallback = 1;

	if (socktype == SOCK_RAW || do_fallback) {
		socktype = SOCK_RAW;
		sock->fd = socket(family, SOCK_RAW, protocol);
	}

	if (sock->fd == -1) {
		/* Report error related to disabled IPv6 only when IPv6 also failed or in
		 * verbose mode. Report other errors always.
		 */
		if ((errno == EAFNOSUPPORT && socktype == AF_INET6) || data->options & F_VERBOSE || requisite)
			fprintf(stderr, "ping: socket: %s\n", strerror(errno));
		if (requisite)
			return 0;
	} else
		sock->socktype = socktype;

	return 1;
}

void ping4_reset(void)
{
	memset(&data,0, sizeof data);
	data.blocking = 0;
	data.interval = 1000;
	data.preload = 1;
	data.lingertime = 1000;
	data.confirm = 0;
	data.npackets = 1;
	data.broadcast_pings = 0;
	data.source.sin_family = AF_INET;
	data.pmtudisc = -1;
	data.in_pr_addr = 0;
	data.tmin = LONG_MAX;
	data.confirm_flag = MSG_CONFIRM;
	data.screen_width = INT_MAX;
}

int ping4_api(char *target)
{
	int hold, packlen;
	unsigned char *packet;
	char hnamebuf[NI_MAXHOST];
	unsigned char rspace[3 + 4 * NROUTES + 1];	/* record route space */
	__u32 *tmp_rspace;
	int optlen = 0;
	int nroute = 0;
	__u32 route[10] = {0};
	struct addrinfo *result = NULL;

	struct ping_func_set_st ping4_func_set = {
		.send_probe = ping4_send_probe,
		.receive_error_msg = ping4_receive_error_msg,
		.parse_reply = ping4_parse_reply,
		.install_filter = ping4_install_filter
	};
	
	struct addrinfo hints = { .ai_family = AF_UNSPEC, .ai_protocol = IPPROTO_UDP, .ai_socktype = SOCK_DGRAM, .ai_flags = getaddrinfo_flags };
	struct addrinfo *ai = NULL;
	socket_st sock = { .fd = -1 };
	
	if (getaddrinfo(target, NULL, &hints, &result)){
		return 0;
	}
	if (result)
		freeaddrinfo(result);

	if (data.blocking)
		return 0;

	data.blocking = 1;

	if(!limit_capabilities(&data))
		return 0;
	
        hints.ai_family = AF_INET;

	/* Create sockets */
	enable_capability_raw(&data);
	if(!create_socket(&sock, AF_INET, hints.ai_socktype, IPPROTO_ICMP, hints.ai_family == AF_INET, &data))
		return 0;
	disable_capability_raw(&data);

	/* Set socket options */
	memset((char *)&data.whereto, 0, sizeof(data.whereto));
	data.whereto.sin_family = AF_INET;
	if (inet_aton(target, &data.whereto.sin_addr) == 1) {
		data.hostname = target;
		if (target == NULL)
			data.options |= F_NUMERIC;
	} else {
		struct addrinfo *result = NULL;
		int status;

		if ( target != NULL || !ai) {
			status = getaddrinfo(target, NULL, &hints, &result);
			if (status) {
				fprintf(stderr, "ping: %s: %s\n", target, gai_strerror(status));
				return -1;
			}
			ai = result;
		}

		memcpy(&data.whereto, ai->ai_addr, sizeof data.whereto);
		memset(hnamebuf, 0, sizeof hnamebuf);
		if (ai->ai_canonname)
			strncpy(hnamebuf, ai->ai_canonname, sizeof hnamebuf - 1);
		data.hostname = hnamebuf;

		if (result)
			freeaddrinfo(result);
	}

	if (target != NULL)
		route[nroute++] = data.whereto.sin_addr.s_addr;

	if (data.source.sin_addr.s_addr == 0) {
		socklen_t alen;
		struct sockaddr_in dst = data.whereto;
		int probe_fd = socket(AF_INET, SOCK_DGRAM, 0);

		if (probe_fd < 0) {
			perror("socket");
			return -1;
		}
		if (data.device) {
			struct ifreq ifr;
			int i;
			int fds[2] = {probe_fd, sock.fd};

			memset(&ifr, 0, sizeof(ifr));
			strncpy(ifr.ifr_name, data.device, IFNAMSIZ-1);

			for (i = 0; i < 2; i++) {
				int fd = fds[i];
				int rc;
				enable_capability_raw(&data);
				rc = setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, data.device, strlen(data.device)+1);
				disable_capability_raw(&data);

				if (rc == -1) {
					if (IN_MULTICAST(ntohl(dst.sin_addr.s_addr))) {
						struct ip_mreqn imr;
						if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
							fprintf(stderr, "ping: unknown iface %s\n", data.device);
							return -1;
						}
						memset(&imr, 0, sizeof(imr));
						imr.imr_ifindex = ifr.ifr_ifindex;
						if (setsockopt(fd, SOL_IP, IP_MULTICAST_IF, &imr, sizeof(imr)) == -1) {
							perror("ping: IP_MULTICAST_IF");
							return -1;
						}
					} else {
						perror("ping: SO_BINDTODEVICE");
						return -1;
					}
				}
			}
		}

		dst.sin_port = htons(1025);
		if (nroute)
			dst.sin_addr.s_addr = route[0];
		if (connect(probe_fd, (struct sockaddr*)&dst, sizeof(dst)) == -1) {
			if (errno == EACCES) {
				if (data.broadcast_pings == 0) {
					fprintf(stderr,
						"Do you want to ping broadcast? Then -b. If not, check your local firewall rules.\n");
					return -1;
				}
				fprintf(stderr, "WARNING: pinging broadcast address\n");
				if (setsockopt(probe_fd, SOL_SOCKET, SO_BROADCAST,
					       &data.broadcast_pings, sizeof(data.broadcast_pings)) < 0) {
					perror ("can't set broadcasting");
					return -1;
				}
				if (connect(probe_fd, (struct sockaddr*)&dst, sizeof(dst)) == -1) {
					perror("connect");
					return -1;
				}
			} else {
				perror("connect");
				return -1;
			}
		}
		alen = sizeof(data.source);
		if (getsockname(probe_fd, (struct sockaddr*)&data.source, &alen) == -1) {
			perror("getsockname");
			return -1;
		}
		data.source.sin_port = 0;

#ifndef WITHOUT_IFADDRS
		if (data.device) {
			struct ifaddrs *ifa0, *ifa;
			int ret;

			ret = getifaddrs(&ifa0);
			if (ret) {
				fprintf(stderr, "gatifaddrs() failed.\n");
				return -1;
			}
			for (ifa = ifa0; ifa; ifa = ifa->ifa_next) {
				if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET)
					continue;
				if (!strncmp(ifa->ifa_name, data.device, sizeof(data.device) - 1) &&
				    !memcmp(&((struct sockaddr_in *)ifa->ifa_addr)->sin_addr,
					    &data.source.sin_addr, sizeof(data.source.sin_addr)))
					break;
			}
			freeifaddrs(ifa0);
			if (!ifa)
				fprintf(stderr, "ping: Warning: source address might be selected on device other than %s.\n", data.device);
		}
#endif
		close(probe_fd);
	} while (0);

	if (data.whereto.sin_addr.s_addr == 0)
		data.whereto.sin_addr.s_addr = data.source.sin_addr.s_addr;

	if (data.device) {
		struct ifreq ifr;

		memset(&ifr, 0, sizeof(ifr));
		strncpy(ifr.ifr_name, data.device, IFNAMSIZ-1);
		if (ioctl(sock.fd, SIOCGIFINDEX, &ifr) < 0) {
			fprintf(stderr, "ping: unknown iface %s\n", data.device);
			return -1;
		}
	}

	if (data.broadcast_pings || IN_MULTICAST(ntohl(data.whereto.sin_addr.s_addr))) {
		if (data.uid) {
			if (data.interval < 1000) {
				fprintf(stderr, "ping: broadcast ping with too short interval.\n");
				return -1;
			}
			if (data.pmtudisc >= 0 && data.pmtudisc != IP_PMTUDISC_DO) {
				fprintf(stderr, "ping: broadcast ping does not fragment.\n");
				return -1;
			}
		}
		if (data.pmtudisc < 0)
			data.pmtudisc = IP_PMTUDISC_DO;
	}

	if (data.pmtudisc >= 0) {
		if (setsockopt(sock.fd, SOL_IP, IP_MTU_DISCOVER, &data.pmtudisc, sizeof data.pmtudisc) == -1) {
			perror("ping: IP_MTU_DISCOVER");
			return -1;
		}
	}

	if ((data.options&F_STRICTSOURCE) &&
	    bind(sock.fd, (struct sockaddr *) &data.source, sizeof data.source) == -1) {
		perror("bind");
		return -1;
	}

	if (sock.socktype == SOCK_RAW) {
		struct icmp_filter filt;
		filt.data = ~((1<<ICMP_SOURCE_QUENCH)|
			      (1<<ICMP_DEST_UNREACH)|
			      (1<<ICMP_TIME_EXCEEDED)|
			      (1<<ICMP_PARAMETERPROB)|
			      (1<<ICMP_REDIRECT)|
			      (1<<ICMP_ECHOREPLY));
		if (setsockopt(sock.fd, SOL_RAW, ICMP_FILTER, &filt, sizeof filt) == -1)
			perror("WARNING: setsockopt(ICMP_FILTER)");
	}

	hold = 1;
	if (setsockopt(sock.fd, SOL_IP, IP_RECVERR, &hold, sizeof hold))
		fprintf(stderr, "WARNING: your kernel is veeery old. No problems.\n");

	if (sock.socktype == SOCK_DGRAM) {
		if (setsockopt(sock.fd, SOL_IP, IP_RECVTTL, &hold, sizeof hold))
			perror("WARNING: setsockopt(IP_RECVTTL)");
		if (setsockopt(sock.fd, SOL_IP, IP_RETOPTS, &hold, sizeof hold))
			perror("WARNING: setsockopt(IP_RETOPTS)");
	}

	/* record route option */
	if (data.options & F_RROUTE) {
		memset(rspace, 0, sizeof(rspace));
		rspace[0] = IPOPT_NOP;
		rspace[1+IPOPT_OPTVAL] = IPOPT_RR;
		rspace[1+IPOPT_OLEN] = sizeof(rspace)-1;
		rspace[1+IPOPT_OFFSET] = IPOPT_MINOFF;
		//optlen = 40;
		if (setsockopt(sock.fd, IPPROTO_IP, IP_OPTIONS, rspace, sizeof rspace) < 0) {
			perror("ping: record route");
			return -1;
		}
	}
	if (data.options & F_TIMESTAMP) {
		memset(rspace, 0, sizeof(rspace));
		rspace[0] = IPOPT_TIMESTAMP;
		rspace[1] = (data.ts_type==IPOPT_TS_TSONLY ? 40 : 36);
		rspace[2] = 5;
		rspace[3] = data.ts_type;
		if (data.ts_type == IPOPT_TS_PRESPEC) {
			int i;
			rspace[1] = 4+nroute*8;
			for (i = 0; i < nroute; i++) {
				tmp_rspace = (__u32*)&rspace[4+i*8];
				*tmp_rspace = route[i];
			}
		}
		if (setsockopt(sock.fd, IPPROTO_IP, IP_OPTIONS, rspace, rspace[1]) < 0) {
			rspace[3] = 2;
			if (setsockopt(sock.fd, IPPROTO_IP, IP_OPTIONS, rspace, rspace[1]) < 0) {
				perror("ping: ts option");
				return -1;
			}
		}
		optlen = 40;
	}
	if (data.options & F_SOURCEROUTE) {
		int i;
		memset(rspace, 0, sizeof(rspace));
		rspace[0] = IPOPT_NOOP;
		rspace[1+IPOPT_OPTVAL] = (data.options & F_SO_DONTROUTE) ? IPOPT_SSRR
			: IPOPT_LSRR;
		rspace[1+IPOPT_OLEN] = 3 + nroute*4;
		rspace[1+IPOPT_OFFSET] = IPOPT_MINOFF;
		for (i = 0; i < nroute; i++) {
			tmp_rspace = (__u32*)&rspace[4+i*4];
			*tmp_rspace = route[i];
		}

		if (setsockopt(sock.fd, IPPROTO_IP, IP_OPTIONS, rspace, 4 + nroute*4) < 0) {
			perror("ping: record route");
			return -1;
		}
		optlen = 40;
	}

	/* Estimate memory eaten by single packet. It is rough estimate.
	 * Actually, for small datalen's it depends on kernel side a lot. */
	hold = data.datalen + 8;
	hold += ((hold+511)/512)*(optlen + 20 + 16 + 64 + 160);
	sock_setbufs(&sock, hold, &data);

	if (data.broadcast_pings) {
		if (setsockopt(sock.fd, SOL_SOCKET, SO_BROADCAST, &data.broadcast_pings, sizeof data.broadcast_pings) < 0) {
			perror ("ping: can't set broadcasting");
			return -1;
		}
	}

	if (data.options & F_NOLOOP) {
		int loop = 0;
		if (setsockopt(sock.fd, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof loop) == -1) {
			perror ("ping: can't disable multicast loopback");
			return -1;
		}
	}
	if (data.options & F_TTL) {
		int ittl = data.ttl;
		if (setsockopt(sock.fd, IPPROTO_IP, IP_MULTICAST_TTL, &data.ttl, sizeof data.ttl) == -1) {
			perror ("ping: can't set multicast time-to-live");
			return -1;
		}
		if (setsockopt(sock.fd, IPPROTO_IP, IP_TTL, &ittl, sizeof ittl) == -1) {
			perror ("ping: can't set unicast time-to-live");
			return -1;
		}
	}

	if (data.datalen > 0xFFFF - 8 - optlen - 20) {
		fprintf(stderr, "Error: packet size %d is too large. Maximum is %d\n", data.datalen, 0xFFFF-8-20-optlen);
		return -1;
	}

	if (data.datalen >= sizeof(struct timeval))	/* can we time transfer */
		data.timing = 1;
	packlen = data.datalen + MAXIPLEN + MAXICMPLEN;
	if (!(packet = (unsigned char *)malloc((unsigned int)packlen))) {
		fprintf(stderr, "ping: out of memory.\n");
		return -1;
	}

#ifdef DEBUG
	printf("PING %s (%s) ", data.hostname, inet_ntoa(data.whereto.sin_addr));
	if (data.device || (data.options&F_STRICTSOURCE))
		printf("from %s %s: ", inet_ntoa(data.source.sin_addr), data.device ?: "");
	printf("%d(%d) bytes of data.\n", data.datalen, data.datalen+8+optlen+20);
#endif

	if(!setup(&sock, &data))
		return 0;

	return main_loop(&ping4_func_set, &sock, packet, packlen, &data);
}

int ping4_receive_error_msg(socket_st *sock, struct gbl_data *data)
{
	int res;
	char cbuf[512];
	struct iovec  iov;
	struct msghdr msg;
	struct cmsghdr *cmsg;
	struct sock_extended_err *e;
	struct icmphdr icmph;
	struct sockaddr_in target;
	int net_errors = 0;
	int local_errors = 0;
	int saved_errno = errno;

	iov.iov_base = &icmph;
	iov.iov_len = sizeof(icmph);
	msg.msg_name = (void*)&target;
	msg.msg_namelen = sizeof(target);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_flags = 0;
	msg.msg_control = cbuf;
	msg.msg_controllen = sizeof(cbuf);

	res = recvmsg(sock->fd, &msg, MSG_ERRQUEUE|MSG_DONTWAIT);
	if (res < 0)
		goto out;

	e = NULL;
	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level == SOL_IP) {
			if (cmsg->cmsg_type == IP_RECVERR)
				e = (struct sock_extended_err *)CMSG_DATA(cmsg);
		}
	}
	if (e == NULL)
		abort();

	if (e->ee_origin == SO_EE_ORIGIN_LOCAL) {
		local_errors++;
		if (data->options & F_QUIET)
			goto out;
		if (data->options & F_FLOOD)
			write_stdout("E", 1);
		else if (e->ee_errno != EMSGSIZE)
			fprintf(stderr, "ping: local error: %s\n", strerror(e->ee_errno));
		else
			fprintf(stderr, "ping: local error: Message too long, mtu=%u\n", e->ee_info);
		data->nerrors++;
	} else if (e->ee_origin == SO_EE_ORIGIN_ICMP) {
#ifdef DEBUG
		struct sockaddr_in *sin = (struct sockaddr_in*)(e+1);
#endif

		if (res < sizeof(icmph) ||
		    target.sin_addr.s_addr != data->whereto.sin_addr.s_addr ||
		    icmph.type != ICMP_ECHO ||
		    !is_ours(sock, icmph.un.echo.id, data)) {
			/* Not our error, not an error at all. Clear. */
			saved_errno = 0;
			goto out;
		}

		acknowledge(ntohs(icmph.un.echo.sequence), data);

		net_errors++;
		data->nerrors++;
		if (data->options & F_QUIET)
			goto out;
		if (data->options & F_FLOOD) {
			write_stdout("\bE", 2);
		} else {

#ifdef DEBUG
			print_timestamp(data);
			printf("From %s icmp_seq=%u ", pr_addr(sin, sizeof *sin, data), ntohs(icmph.un.echo.sequence));
#endif
			pr_icmph(e->ee_type, e->ee_code, e->ee_info, NULL, data);
			fflush(stdout);
		}
	}

out:
	errno = saved_errno;
	return net_errors ? : -local_errors;
}

/*
 * pinger --
 * 	Compose and transmit an ICMP ECHO REQUEST packet.  The IP packet
 * will be added on by the kernel.  The ID field is our UNIX process ID,
 * and the sequence number is an ascending integer.  The first 8 bytes
 * of the data portion are used to hold a UNIX "timeval" struct in VAX
 * byte-order, to compute the round-trip time.
 */
int ping4_send_probe(socket_st *sock, void *packet, unsigned packet_size, struct gbl_data *data)
{
	struct icmphdr *icp;
	int cc;
	int i;

	icp = (struct icmphdr *)packet;
	icp->type = ICMP_ECHO;
	icp->code = 0;
	icp->checksum = 0;
	icp->un.echo.sequence = htons(data->ntransmitted+1);
	icp->un.echo.id = data->ident;			/* ID */

	rcvd_clear(data->ntransmitted+1, data);

	if (data->timing) {
		if (data->options&F_LATENCY) {
			struct timeval tmp_tv;
			gettimeofday(&tmp_tv, NULL);
			memcpy(icp+1, &tmp_tv, sizeof(tmp_tv));
		} else {
			memset(icp+1, 0, sizeof(struct timeval));
		}
	}

	cc = data->datalen + 8;			/* skips ICMP portion */

	/* compute ICMP checksum here */
	icp->checksum = in_cksum((unsigned short *)icp, cc, 0);

	if (data->timing && !(data->options&F_LATENCY)) {
		struct timeval tmp_tv;
		gettimeofday(&tmp_tv, NULL);
		memcpy(icp+1, &tmp_tv, sizeof(tmp_tv));
		icp->checksum = in_cksum((unsigned short *)&tmp_tv, sizeof(tmp_tv), ~icp->checksum);
	}

	i = sendto(sock->fd, icp, cc, 0, (struct sockaddr*)&data->whereto, sizeof(data->whereto));

	return (cc == i ? 0 : i);
}

/*
 * parse_reply --
 *	Print out the packet, if it came from us.  This logic is necessary
 * because ALL readers of the ICMP socket get a copy of ALL ICMP packets
 * which arrive ('tis only fair).  This permits multiple copies of this
 * program to be run without having intermingled output (or statistics!).
 */
static
void pr_echo_reply(__u8 *_icp, int len)
{
#ifdef DEBUG
	struct icmphdr *icp = (struct icmphdr *)_icp;
	printf(" icmp_seq=%u", ntohs(icp->un.echo.sequence));
#endif
}

int
ping4_parse_reply(struct socket_st *sock, struct msghdr *msg, int cc, void *addr, struct timeval *tv, struct gbl_data *data)
{
	struct sockaddr_in *from = addr;
	__u8 *buf = msg->msg_iov->iov_base;
	struct icmphdr *icp;
	struct iphdr *ip;
	int hlen;
	int csfailed;
	struct cmsghdr *cmsg;
	int ttl;
	__u8 *opts, *tmp_ttl;
	int optlen;

	/* Check the IP header */
	ip = (struct iphdr *)buf;
	if (sock->socktype == SOCK_RAW) {
		hlen = ip->ihl*4;
		if (cc < hlen + 8 || ip->ihl < 5) {
			if (data->options & F_VERBOSE)
				fprintf(stderr, "ping: packet too short (%d bytes) from %s\n", cc,
					pr_addr(from, sizeof *from, data));
			return 1;
		}
		ttl = ip->ttl;
		opts = buf + sizeof(struct iphdr);
		optlen = hlen - sizeof(struct iphdr);
	} else {
		hlen = 0;
		ttl = 0;
		opts = buf;
		optlen = 0;
		for (cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
			if (cmsg->cmsg_level != SOL_IP)
				continue;
			if (cmsg->cmsg_type == IP_TTL) {
				if (cmsg->cmsg_len < sizeof(int))
					continue;
				tmp_ttl = (__u8 *) CMSG_DATA(cmsg);
				ttl = (int)*tmp_ttl;
			} else if (cmsg->cmsg_type == IP_RETOPTS) {
				opts = (__u8 *) CMSG_DATA(cmsg);
				optlen = cmsg->cmsg_len;
			}
		}
	}

	/* Now the ICMP part */
	cc -= hlen;
	icp = (struct icmphdr *)(buf + hlen);
	csfailed = in_cksum((unsigned short *)icp, cc, 0);

	if (icp->type == ICMP_ECHOREPLY) {
		if (!is_ours(sock, icp->un.echo.id, data))
			return 1;			/* 'Twas not our ECHO */
		if (!contains_pattern_in_payload((__u8*)(icp+1), data))
			return 1;			/* 'Twas really not our ECHO */
		if (gather_statistics((__u8*)icp, sizeof(*icp), cc,
				      ntohs(icp->un.echo.sequence),
				      ttl, csfailed, tv, pr_addr(from, sizeof *from, data),
				      pr_echo_reply, data)) {
			fflush(stdout);
			return 0;
		}
	} else {
		/* We fall here when a redirect or source quench arrived. */

		switch (icp->type) {
		case ICMP_ECHO:
			/* MUST NOT */
			return 1;
		case ICMP_SOURCE_QUENCH:
		case ICMP_REDIRECT:
		case ICMP_DEST_UNREACH:
		case ICMP_TIME_EXCEEDED:
		case ICMP_PARAMETERPROB:
			{
				struct iphdr * iph = (struct  iphdr *)(&icp[1]);
				struct icmphdr *icp1 = (struct icmphdr*)((unsigned char *)iph + iph->ihl*4);
				int error_pkt;
				if (cc < 8+sizeof(struct iphdr)+8 ||
				    cc < 8+iph->ihl*4+8)
					return 1;
				if (icp1->type != ICMP_ECHO ||
				    iph->daddr != data->whereto.sin_addr.s_addr ||
				    !is_ours(sock, icp1->un.echo.id, data))
					return 1;
				error_pkt = (icp->type != ICMP_REDIRECT &&
					     icp->type != ICMP_SOURCE_QUENCH);
				if (error_pkt) {
					acknowledge(ntohs(icp1->un.echo.sequence), data);
					return 0;
				}
				if (data->options & (F_QUIET | F_FLOOD))
					return 1;
				print_timestamp(data);
#ifdef DEBUG
				printf("From %s: icmp_seq=%u ",
				       pr_addr(from, sizeof *from, data),
				       ntohs(icp1->un.echo.sequence));
				if (csfailed)
					printf("(BAD CHECKSUM)");
				pr_icmph(icp->type, icp->code, ntohl(icp->un.gateway), icp, data);
#endif
				return 1;
			}
		default:
			/* MUST NOT */
			break;
		}
		if ((data->options & F_FLOOD) && !(data->options & (F_VERBOSE|F_QUIET))) {
			if (!csfailed)
				write_stdout("!E", 2);
			else
				write_stdout("!EC", 3);
			return 0;
		}
		if (!(data->options & F_VERBOSE) || data->uid)
			return 0;
		if (data->options & F_PTIMEOFDAY) {
			struct timeval recv_time;
			gettimeofday(&recv_time, NULL);
			printf("%lu.%06lu ", (unsigned long)recv_time.tv_sec, (unsigned long)recv_time.tv_usec);
		}
		printf("From %s: ", pr_addr(from, sizeof *from, data));
		if (csfailed) {
			printf("(BAD CHECKSUM)\n");
			return 0;
		}
		pr_icmph(icp->type, icp->code, ntohl(icp->un.gateway), icp, data);
		return 0;
	}

	if (data->options & F_AUDIBLE) {
		putchar('\a');
		if(data->options & F_FLOOD)
			fflush(stdout);
	}
	if (!(data->options & F_FLOOD)) {
		pr_options(opts, optlen + sizeof(struct iphdr), data);
#ifdef DEBUG	
		putchar('\n');
#endif
		fflush(stdout);
	}
	return 0;
}


#if BYTE_ORDER == LITTLE_ENDIAN
# define ODDBYTE(v)	(v)
#elif BYTE_ORDER == BIG_ENDIAN
# define ODDBYTE(v)	((unsigned short)(v) << 8)
#else
# define ODDBYTE(v)	htons((unsigned short)(v) << 8)
#endif

unsigned short
in_cksum(const unsigned short *addr, register int len, unsigned short csum)
{
	register int nleft = len;
	const unsigned short *w = addr;
	register unsigned short answer;
	register int sum = csum;

	/*
	 *  Our algorithm is simple, using a 32 bit accumulator (sum),
	 *  we add sequential 16 bit words to it, and at the end, fold
	 *  back all the carry bits from the top 16 bits into the lower
	 *  16 bits.
	 */
	while (nleft > 1)  {
		sum += *w++;
		nleft -= 2;
	}

	/* mop up an odd byte, if necessary */
	if (nleft == 1)
		sum += ODDBYTE(*(unsigned char *)w); /* le16toh() may be unavailable on old systems */

	/*
	 * add back carry outs from top 16 bits to low 16 bits
	 */
	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;				/* truncate to 16 bits */
	return (answer);
}

/*
 * pr_icmph --
 *	Print a descriptive string about an ICMP header.
 */
void pr_icmph(__u8 type, __u8 code, __u32 info, struct icmphdr *icp, struct gbl_data *data)
{
	switch(type) {
	case ICMP_ECHOREPLY:
		printf("Echo Reply\n");
		/* XXX ID + Seq + Data */
		break;
	case ICMP_DEST_UNREACH:
		switch(code) {
		case ICMP_NET_UNREACH:
			printf("Destination Net Unreachable\n");
			break;
		case ICMP_HOST_UNREACH:
			printf("Destination Host Unreachable\n");
			break;
		case ICMP_PROT_UNREACH:
			printf("Destination Protocol Unreachable\n");
			break;
		case ICMP_PORT_UNREACH:
			printf("Destination Port Unreachable\n");
			break;
		case ICMP_FRAG_NEEDED:
			printf("Frag needed and DF set (mtu = %u)\n", info);
			break;
		case ICMP_SR_FAILED:
			printf("Source Route Failed\n");
			break;
		case ICMP_NET_UNKNOWN:
			printf("Destination Net Unknown\n");
			break;
		case ICMP_HOST_UNKNOWN:
			printf("Destination Host Unknown\n");
			break;
		case ICMP_HOST_ISOLATED:
			printf("Source Host Isolated\n");
			break;
		case ICMP_NET_ANO:
			printf("Destination Net Prohibited\n");
			break;
		case ICMP_HOST_ANO:
			printf("Destination Host Prohibited\n");
			break;
		case ICMP_NET_UNR_TOS:
			printf("Destination Net Unreachable for Type of Service\n");
			break;
		case ICMP_HOST_UNR_TOS:
			printf("Destination Host Unreachable for Type of Service\n");
			break;
		case ICMP_PKT_FILTERED:
			printf("Packet filtered\n");
			break;
		case ICMP_PREC_VIOLATION:
			printf("Precedence Violation\n");
			break;
		case ICMP_PREC_CUTOFF:
			printf("Precedence Cutoff\n");
			break;
		default:
			printf("Dest Unreachable, Bad Code: %d\n", code);
			break;
		}
		if (icp && (data->options & F_VERBOSE))
			pr_iph((struct iphdr*)(icp + 1), data);
		break;
	case ICMP_SOURCE_QUENCH:
		printf("Source Quench\n");
		if (icp && (data->options & F_VERBOSE))
			pr_iph((struct iphdr*)(icp + 1), data);
		break;
	case ICMP_REDIRECT:
		switch(code) {
		case ICMP_REDIR_NET:
			printf("Redirect Network");
			break;
		case ICMP_REDIR_HOST:
			printf("Redirect Host");
			break;
		case ICMP_REDIR_NETTOS:
			printf("Redirect Type of Service and Network");
			break;
		case ICMP_REDIR_HOSTTOS:
			printf("Redirect Type of Service and Host");
			break;
		default:
			printf("Redirect, Bad Code: %d", code);
			break;
		}
		{
			struct sockaddr_in sin = { .sin_family = AF_INET, .sin_addr =  { icp ? icp->un.gateway : info } };

			printf("(New nexthop: %s)\n", pr_addr(&sin, sizeof sin, data));
		}
		if (icp && (data->options & F_VERBOSE))
			pr_iph((struct iphdr*)(icp + 1), data);
		break;
	case ICMP_ECHO:
		printf("Echo Request\n");
		/* XXX ID + Seq + Data */
		break;
	case ICMP_TIME_EXCEEDED:
		switch(code) {
		case ICMP_EXC_TTL:
			printf("Time to live exceeded\n");
			break;
		case ICMP_EXC_FRAGTIME:
			printf("Frag reassembly time exceeded\n");
			break;
		default:
			printf("Time exceeded, Bad Code: %d\n", code);
			break;
		}
		if (icp && (data->options & F_VERBOSE))
			pr_iph((struct iphdr*)(icp + 1), data);
		break;
	case ICMP_PARAMETERPROB:
		printf("Parameter problem: pointer = %u\n", icp ? (ntohl(icp->un.gateway)>>24) : info);
		if (icp && (data->options & F_VERBOSE))
			pr_iph((struct iphdr*)(icp + 1), data);
		break;
	case ICMP_TIMESTAMP:
		printf("Timestamp\n");
		/* XXX ID + Seq + 3 timestamps */
		break;
	case ICMP_TIMESTAMPREPLY:
		printf("Timestamp Reply\n");
		/* XXX ID + Seq + 3 timestamps */
		break;
	case ICMP_INFO_REQUEST:
		printf("Information Request\n");
		/* XXX ID + Seq */
		break;
	case ICMP_INFO_REPLY:
		printf("Information Reply\n");
		/* XXX ID + Seq */
		break;
#ifdef ICMP_MASKREQ
	case ICMP_MASKREQ:
		printf("Address Mask Request\n");
		break;
#endif
#ifdef ICMP_MASKREPLY
	case ICMP_MASKREPLY:
		printf("Address Mask Reply\n");
		break;
#endif
	default:
		printf("Bad ICMP type: %d\n", type);
	}
}

void pr_options(unsigned char * cp, int hlen, struct gbl_data *data)
{
	int i, j;
	int optlen, totlen;
	unsigned char * optptr;
	static int old_rrlen;
	static char old_rr[MAX_IPOPTLEN];

	totlen = hlen-sizeof(struct iphdr);
	optptr = cp;

	while (totlen > 0) {
		if (*optptr == IPOPT_EOL)
			break;
		if (*optptr == IPOPT_NOP) {
			totlen--;
			optptr++;
			printf("\nNOP");
			continue;
		}
		cp = optptr;
		optlen = optptr[1];
		if (optlen < 2 || optlen > totlen)
			break;

		switch (*cp) {
		case IPOPT_SSRR:
		case IPOPT_LSRR:
			printf("\n%cSRR: ", *cp==IPOPT_SSRR ? 'S' : 'L');
			j = *++cp;
			cp++;
			if (j > IPOPT_MINOFF) {
				for (;;) {
					__u32 address;
					memcpy(&address, cp, 4);
					cp += 4;
					if (address == 0)
						printf("\t0.0.0.0");
					else {
						struct sockaddr_in sin = { .sin_family = AF_INET, .sin_addr = { address } };

						printf("\t%s", pr_addr(&sin, sizeof sin, data));
					}
					j -= 4;
					putchar('\n');
					if (j <= IPOPT_MINOFF)
						break;
				}
			}
			break;
		case IPOPT_RR:
			j = *++cp;		/* get length */
			i = *++cp;		/* and pointer */
			if (i > j)
				i = j;
			i -= IPOPT_MINOFF;
			if (i <= 0)
				break;
			if (i == old_rrlen
			    && !memcmp(cp, old_rr, i)
			    && !(data->options & F_FLOOD)) {
				printf("\t(same route)");
				break;
			}
			old_rrlen = i;
			memcpy(old_rr, (char *)cp, i);
			printf("\nRR: ");
			cp++;
			for (;;) {
				__u32 address;
				memcpy(&address, cp, 4);
				cp += 4;
				if (address == 0)
					printf("\t0.0.0.0");
				else {
					struct sockaddr_in sin = { .sin_family = AF_INET, .sin_addr = { address } };

					printf("\t%s", pr_addr(&sin, sizeof sin, data));
				}
				i -= 4;
				putchar('\n');
				if (i <= 0)
					break;
			}
			break;
		case IPOPT_TS:
		{
			int stdtime = 0, nonstdtime = 0;
			__u8 flags;
			j = *++cp;		/* get length */
			i = *++cp;		/* and pointer */
			if (i > j)
				i = j;
			i -= 5;
			if (i <= 0)
				break;
			flags = *++cp;
			printf("\nTS: ");
			cp++;
			for (;;) {
				long l;

				if ((flags&0xF) != IPOPT_TS_TSONLY) {
					__u32 address;
					memcpy(&address, cp, 4);
					cp += 4;
					if (address == 0)
						printf("\t0.0.0.0");
					else {
						struct sockaddr_in sin = { .sin_family = AF_INET, .sin_addr = { address } };

						printf("\t%s", pr_addr(&sin, sizeof sin, data));
					}
					i -= 4;
					if (i <= 0)
						break;
				}
				l = *cp++;
				l = (l<<8) + *cp++;
				l = (l<<8) + *cp++;
				l = (l<<8) + *cp++;

				if  (l & 0x80000000) {
					if (nonstdtime==0)
						printf("\t%ld absolute not-standard", l&0x7fffffff);
					else
						printf("\t%ld not-standard", (l&0x7fffffff) - nonstdtime);
					nonstdtime = l&0x7fffffff;
				} else {
					if (stdtime==0)
						printf("\t%ld absolute", l);
					else
						printf("\t%ld", l - stdtime);
					stdtime = l;
				}
				i -= 4;
				putchar('\n');
				if (i <= 0)
					break;
			}
			if (flags>>4)
				printf("Unrecorded hops: %d\n", flags>>4);
			break;
		}
		default:
			printf("\nunknown option %x", *cp);
			break;
		}
		totlen -= optlen;
		optptr += optlen;
	}
}


/*
 * pr_iph --
 *	Print an IP header with options.
 */
void pr_iph(struct iphdr *ip, struct gbl_data *data)
{
	int hlen;
	unsigned char *cp;

	hlen = ip->ihl << 2;
	cp = (unsigned char *)ip + 20;		/* point to options */

	printf("Vr HL TOS  Len   ID Flg  off TTL Pro  cks      Src      Dst Data\n");
	printf(" %1x  %1x  %02x %04x %04x",
	       ip->version, ip->ihl, ip->tos, ip->tot_len, ip->id);
	printf("   %1x %04x", ((ip->frag_off) & 0xe000) >> 13,
	       (ip->frag_off) & 0x1fff);
	printf("  %02x  %02x %04x", ip->ttl, ip->protocol, ip->check);
	printf(" %s ", inet_ntoa(*(struct in_addr *)&ip->saddr));
	printf(" %s ", inet_ntoa(*(struct in_addr *)&ip->daddr));
	printf("\n");
	pr_options(cp, hlen, data);
}

/*
 * pr_addr --
 *
 * Return an ascii host address optionally with a hostname.
 */
char *
pr_addr(void *sa, socklen_t salen, struct gbl_data *data)
{
	static char buffer[4096] = "";
	static struct sockaddr_storage last_sa = { 0 };
	static socklen_t last_salen = 0;
	char name[NI_MAXHOST] = "";
	char address[NI_MAXHOST] = "";

	if (salen == last_salen && !memcmp(sa, &last_sa, salen))
		return buffer;

	memcpy(&last_sa, sa, (last_salen = salen));

	data->in_pr_addr = !setjmp(data->pr_addr_jmp);

	getnameinfo(sa, salen, address, sizeof address, NULL, 0, getnameinfo_flags | NI_NUMERICHOST);
	if (!data->exiting && !(data->options & F_NUMERIC))
		getnameinfo(sa, salen, name, sizeof name, NULL, 0, getnameinfo_flags);

	if (*name)
		snprintf(buffer, sizeof buffer, "%s (%s)", name, address);
	else
		snprintf(buffer, sizeof buffer, "%s", address);

	data->in_pr_addr = 0;

	return(buffer);
}


void ping4_install_filter(socket_st *sock, struct gbl_data *data)
{
	static int once;
	static struct sock_filter insns[] = {
		BPF_STMT(BPF_LDX|BPF_B|BPF_MSH, 0), /* Skip IP header. F..g BSD... Look into ping6. */
		BPF_STMT(BPF_LD|BPF_H|BPF_IND, 4), /* Load icmp echo ident */
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 0xAAAA, 0, 1), /* Ours? */
		BPF_STMT(BPF_RET|BPF_K, ~0U), /* Yes, it passes. */
		BPF_STMT(BPF_LD|BPF_B|BPF_IND, 0), /* Load icmp type */
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, ICMP_ECHOREPLY, 1, 0), /* Echo? */
		BPF_STMT(BPF_RET|BPF_K, 0xFFFFFFF), /* No. It passes. */
		BPF_STMT(BPF_RET|BPF_K, 0) /* Echo with wrong ident. Reject. */
	};
	static struct sock_fprog filter = {
		sizeof insns / sizeof(insns[0]),
		insns
	};

	if (once)
		return;
	once = 1;

	/* Patch bpflet for current identifier. */
	insns[2] = (struct sock_filter)BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, htons(data->ident), 0, 1);

	if (setsockopt(sock->fd, SOL_SOCKET, SO_ATTACH_FILTER, &filter, sizeof(filter)))
		perror("WARNING: failed to install socket filter\n");
}

