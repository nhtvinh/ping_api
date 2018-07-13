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

#include "ping.h"

#ifndef HZ
#define HZ sysconf(_SC_CLK_TCK)
#endif

#define ARRAY_SIZE(a)	(sizeof(a) / sizeof(a[0]))

int limit_capabilities(struct gbl_data *data)
{
	data->uid = getuid();
	data->euid = geteuid();

	if (seteuid(data->uid)) {
		perror("ping: setuid");
		return 0;
	}

	return 1;
}

int modify_capability(int on, struct gbl_data *data)
{
	if (seteuid(on ? data->euid : getuid())) {
		perror("seteuid");
		return -1;
	}

	return 0;
}

static inline int enable_capability_admin(struct gbl_data *dt)		{ return modify_capability(1, dt); };
static inline int disable_capability_admin(struct gbl_data *dt)		{ return modify_capability(0, dt); };

static void sigexit(int signo)
{
	data.exiting = 1;
	if (data.in_pr_addr)
		longjmp(data.pr_addr_jmp, 0);
}

static void sigstatus(int signo)
{
	data.status_snapshot = 1;
}

int __schedule_exit(int next, struct gbl_data *data)
{
	static unsigned long waittime;
	struct itimerval it;

	if (waittime)
		return next;

	if (data->nreceived) {
		waittime = 2 * data->tmax;
		if (waittime < 1000*data->interval)
			waittime = 1000*data->interval;
	} else
		waittime = data->lingertime*1000;

	if (next < 0 || next < waittime/1000)
		next = waittime/1000;

	it.it_interval.tv_sec = 0;
	it.it_interval.tv_usec = 0;
	it.it_value.tv_sec = waittime/1000000;
	it.it_value.tv_usec = waittime%1000000;
	setitimer(ITIMER_REAL, &it, NULL);
	return next;
}

static inline void update_interval(struct gbl_data *data)
{
	int est = data->rtt ? data->rtt/8 : data->interval*1000;

	data->interval = (est+data->rtt_addend+500)/1000;
	if (data->uid && data->interval < MINUSERINTERVAL)
		data->interval = MINUSERINTERVAL;
}

/*
 * Print timestamp
 */
void print_timestamp(struct gbl_data *data)
{
	if (data->options & F_PTIMEOFDAY) {
		struct timeval tv;
		gettimeofday(&tv, NULL);
#ifdef DEBUG
		printf("[%lu.%06lu] ",
		       (unsigned long)tv.tv_sec, (unsigned long)tv.tv_usec);
#endif
	}
}

/*
 * pinger --
 * 	Compose and transmit an ICMP ECHO REQUEST packet.  The IP packet
 * will be added on by the kernel.  The ID field is our UNIX process ID,
 * and the sequence number is an ascending integer.  The first 8 bytes
 * of the data portion are used to hold a UNIX "timeval" struct in VAX
 * byte-order, to compute the round-trip time.
 */
int pinger(ping_func_set_st *fset, socket_st *sock, struct gbl_data *data)
{
	static int oom_count;
	static int tokens;
	int i;

	/* Have we already sent enough? If we have, return an arbitrary positive value. */
	if (data->exiting || (data->npackets && data->ntransmitted >= data->npackets && data->deadline))
		return 1000;

	/* Check that packets < rate*time + preload */
	if (data->cur_time.tv_sec == 0) {
		gettimeofday(&(data->cur_time), NULL);
		tokens =data->interval*(data->preload-1);
	} else {
		long ntokens;
		struct timeval tv;

		gettimeofday(&tv, NULL);
		ntokens = (tv.tv_sec - data->cur_time.tv_sec)*1000 +
			(tv.tv_usec- data->cur_time.tv_usec)/1000;
		if (data->interval) {
			/* Case of unlimited flood is special;
			 * if we see no reply, they are limited to 100pps */
			if (ntokens < MININTERVAL && in_flight(data) >=data->preload)
				return MININTERVAL-ntokens;
		}
		ntokens += tokens;
		if (ntokens > data->interval*data->preload)
			ntokens = data->interval*data->preload;
		if (ntokens < data->interval)
			return data->interval - ntokens;

		data->cur_time = tv;
		tokens = ntokens - data->interval;
	}

	if (data->options & F_OUTSTANDING) {
		if (data->ntransmitted > 0 && !rcvd_test(data->ntransmitted, data)) {
			print_timestamp(data);
			printf("no answer yet for icmp_seq=%lu\n", (data->ntransmitted % MAX_DUP_CHK));
			fflush(stdout);
		}
	}

resend:
	i = fset->send_probe(sock,data->outpack, sizeof(data->outpack), data);

	if (i == 0) {
		oom_count = 0;
		advance_ntransmitted(data);
		if (!(data->options & F_QUIET) && (data->options & F_FLOOD)) {
			/* Very silly, but without this output with
			 * high preload or pipe size is very confusing. */
			if ((data->preload < data->screen_width && data->pipesize < data->screen_width) ||
			    in_flight(data) < data->screen_width)
				write_stdout(".", 1);
		}
		return data->interval - tokens;
	}

	/* And handle various errors... */
	if (i > 0) {
		/* Apparently, it is some fatal bug. */
		abort();
	} else if (errno == ENOBUFS || errno == ENOMEM) {
		int nores_interval;

		/* Device queue overflow or OOM. Packet is not sent. */
		tokens = 0;
		/* Slowdown. This works only in adaptive mode (option -A) */
		data->rtt_addend += (data->rtt < 8*50000 ? data->rtt/8 : 50000);
		if (data->options&F_ADAPTIVE)
			update_interval(data);
		nores_interval = SCHINT(data->interval/2);
		if (nores_interval > 500)
			nores_interval = 500;
		oom_count++;
		if (oom_count*nores_interval < data->lingertime)
			return nores_interval;
		i = 0;
		/* Fall to hard error. It is to avoid complete deadlock
		 * on stuck output device even when dealine was not requested.
		 * Expected timings are screwed up in any case, but we will
		 * exit some day. :-) */
	} else if (errno == EAGAIN) {
		/* Socket buffer is full. */
		tokens += data->interval;
		return MININTERVAL;
	} else {
		if ((i=fset->receive_error_msg(sock, data)) > 0) {
			/* An ICMP error arrived. In this case, we've received
			 * an error from sendto(), but we've also received an
			 * ICMP message, which means the packet did in fact
			 * send in some capacity. So, in this odd case, report
			 * the more specific errno as the error, and treat this
			 * as a hard local error. */
			i = 0;
			goto hard_local_error;
		}
		/* Compatibility with old linuces. */
		if (i == 0 && data->confirm_flag && errno == EINVAL) {
			data->confirm_flag = 0;
			errno = 0;
		}
		if (!errno)
			goto resend;
	}

hard_local_error:
	/* Hard local error. Pretend we sent packet. */
	advance_ntransmitted(data);

	if (i == 0 && !(data->options & F_QUIET)) {
		if (data->options & F_FLOOD)
			write_stdout("E", 1);
		else
			perror("ping: sendmsg");
	}
	tokens = 0;
	return SCHINT(data->interval);
}

/* Set socket buffers, "alloc" is an estimate of memory taken by single packet. */

void sock_setbufs(socket_st *sock, int alloc, struct gbl_data *data)
{
	int rcvbuf, hold;
	socklen_t tmplen = sizeof(hold);

	if (!data->sndbuf)
		data->sndbuf = alloc;
	setsockopt(sock->fd, SOL_SOCKET, SO_SNDBUF, (char *)&data->sndbuf, sizeof(data->sndbuf));

	rcvbuf = hold = alloc * data->preload;
	if (hold < 65536)
		hold = 65536;
	setsockopt(sock->fd, SOL_SOCKET, SO_RCVBUF, (char *)&hold, sizeof(hold));
	if (getsockopt(sock->fd, SOL_SOCKET, SO_RCVBUF, (char *)&hold, &tmplen) == 0) {
		if (hold < rcvbuf)
			fprintf(stderr, "WARNING: probably, rcvbuf is not enough to hold preload.\n");
	}
}

/* Protocol independent setup and parameter checks. */

int setup(socket_st *sock, struct gbl_data *data)
{
	int hold;
	struct timeval tv;
	sigset_t sset;

	if ((data->options & F_FLOOD) && !(data->options & F_INTERVAL))
		data->interval = 0;

	if (data->uid && data->interval < MINUSERINTERVAL) {
		fprintf(stderr, "ping: cannot flood; minimal interval allowed for user is %dms\n", MINUSERINTERVAL);
		return 0;
	}

	if (data->interval >= INT_MAX/data->preload) {
		fprintf(stderr, "ping: illegal preload and/or interval\n");
		return 0;
	}

	hold = 1;
	if (data->options & F_SO_DEBUG)
		setsockopt(sock->fd, SOL_SOCKET, SO_DEBUG, (char *)&hold, sizeof(hold));
	if (data->options & F_SO_DONTROUTE)
		setsockopt(sock->fd, SOL_SOCKET, SO_DONTROUTE, (char *)&hold, sizeof(hold));

#ifdef SO_TIMESTAMP
	if (!(data->options&F_LATENCY)) {
		int on = 1;
		if (setsockopt(sock->fd, SOL_SOCKET, SO_TIMESTAMP, &on, sizeof(on)))
			fprintf(stderr, "Warning: no SO_TIMESTAMP support, falling back to SIOCGSTAMP\n");
	}
#endif
#ifdef SO_MARK
	if (data->options & F_MARK) {
		int ret;

		enable_capability_admin(data);
		ret = setsockopt(sock->fd, SOL_SOCKET, SO_MARK, &data->mark, sizeof(data->mark));
		disable_capability_admin(data);

		if (ret == -1) {
			/* we probably dont wanna exit since old kernels
			 * dont support mark ..
			*/
			fprintf(stderr, "Warning: Failed to set mark %d\n", data->mark);
		}
	}
#endif

	/* Set some SNDTIMEO to prevent blocking forever
	 * on sends, when device is too slow or stalls. Just put limit
	 * of one second, or "interval", if it is less.
	 */
	tv.tv_sec = 1;
	tv.tv_usec = 0;
	if (data->interval < 1000) {
		tv.tv_sec = 0;
		tv.tv_usec = 1000 * SCHINT(data->interval);
	}
	setsockopt(sock->fd, SOL_SOCKET, SO_SNDTIMEO, (char*)&tv, sizeof(tv));

	/* Set RCVTIMEO to "interval". Note, it is just an optimization
	 * allowing to avoid redundant poll(). */
	tv.tv_sec = SCHINT(data->interval)/1000;
	tv.tv_usec = 1000*(SCHINT(data->interval)%1000);
	if (setsockopt(sock->fd, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(tv)))
		data->options |= F_FLOOD_POLL;

	if (!(data->options & F_PINGFILLED)) {
		int i;
		unsigned char *p = data->outpack+8;

		/* Do not forget about case of small datalen,
		 * fill timestamp area too!
		 */
		for (i = 0; i < data->datalen; ++i)
			*p++ = i;
	}

	if (sock->socktype == SOCK_RAW)
		data->ident = htons(getpid() & 0xFFFF);

	set_signal(SIGINT, sigexit);
	set_signal(SIGALRM, sigexit);
	set_signal(SIGQUIT, sigstatus);

	sigemptyset(&sset);
	sigprocmask(SIG_SETMASK, &sset, NULL);

	gettimeofday(&(data->start_time), NULL);

	if (data->deadline) {
		struct itimerval it;

		it.it_interval.tv_sec = 0;
		it.it_interval.tv_usec = 0;
		it.it_value.tv_sec = data->deadline;
		it.it_value.tv_usec = 0;
		setitimer(ITIMER_REAL, &it, NULL);
	}

	if (isatty(STDOUT_FILENO)) {
		struct winsize w;

		if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) != -1) {
			if (w.ws_col > 0)
				data->screen_width = w.ws_col;
		}
	}

	return 1;
}

/*
 * Return 0 if pattern in payload point to be ptr did not match the pattern that was sent  
 */
int contains_pattern_in_payload(__u8 *ptr, struct gbl_data *data)
{
	int i;
	__u8 *cp, *dp;
 
	/* check the data */
	cp = ((u_char*)ptr) + sizeof(struct timeval);
	dp = &data->outpack[8 + sizeof(struct timeval)];
	for (i = sizeof(struct timeval); i < data->datalen; ++i, ++cp, ++dp) {
		if (*cp != *dp)
			return 0;
	}
	return 1;
}

int finish(struct gbl_data *data)
{
	if (data->ntransmitted && data->nreceived)
		return 1;
	else
		return -1;
}

void status(struct gbl_data *data)
{
	int loss = 0;
	long tavg = 0;

	data->status_snapshot = 0;

	if (data->ntransmitted)
		loss = (((long long)(data->ntransmitted - data->nreceived)) * 100) / data->ntransmitted;

	fprintf(stderr, "\r%ld/%ld packets, %d%% loss", data->nreceived, data->ntransmitted, loss);

	if (data->nreceived && data->timing) {
		tavg = data->tsum / (data->nreceived + data->nrepeats);

		fprintf(stderr, ", min/avg/ewma/max = %ld.%03ld/%lu.%03ld/%d.%03d/%ld.%03ld ms",
		       (long)data->tmin/1000, (long)data->tmin%1000,
		       tavg/1000, tavg%1000,
		       data->rtt/8000, (data->rtt/8)%1000,
		       (long)data->tmax/1000, (long)data->tmax%1000
		       );
	}
	fprintf(stderr, "\n");
}

int main_loop(ping_func_set_st *fset, socket_st *sock, __u8 *packet, int packlen, struct gbl_data *data)
{
	char addrbuf[128];
	char ans_data[4096];
	struct iovec iov;
	struct msghdr msg;
	struct cmsghdr *c;
	int cc;
	int next;
	int polling;
	int recv_error;

	iov.iov_base = (char *)packet;

	for (;;) {
		/* Check exit conditions. */
		if (data->exiting)
			break;
		if (data->npackets && data->nreceived + data->nerrors >= data->npackets)
			break;
		if (data->deadline && data->nerrors)
			break;
		/* Check for and do special actions. */
		if (data->status_snapshot)
			status(data);

		/* Send probes scheduled to this time. */
		do {
			next = pinger(fset, sock, data);
			next = schedule_exit(next, data);
		} while (next <= 0);

		/* "next" is time to send next probe, if positive.
		 * If next<=0 send now or as soon as possible. */

		/* Technical part. Looks wicked. Could be dropped,
		 * if everyone used the newest kernel. :-)
		 * Its purpose is:
		 * 1. Provide intervals less than resolution of scheduler.
		 *    Solution: spinning.
		 * 2. Avoid use of poll(), when recvmsg() can provide
		 *    timed waiting (SO_RCVTIMEO). */
		polling = 0;
		recv_error = 0;
		if ((data->options & (F_ADAPTIVE|F_FLOOD_POLL)) || next<SCHINT(data->interval)) {
			int recv_expected = in_flight(data);

			/* If we are here, recvmsg() is unable to wait for
			 * required timeout. */
			if (1000 % HZ == 0 ? next <= 1000 / HZ : (next < INT_MAX / HZ && next * HZ <= 1000)) {
				/* Very short timeout... So, if we wait for
				 * something, we sleep for MININTERVAL.
				 * Otherwise, spin! */
				if (recv_expected) {
					next = MININTERVAL;
				} else {
					next = 0;
					/* When spinning, no reasons to poll.
					 * Use nonblocking recvmsg() instead. */
					polling = MSG_DONTWAIT;
					/* But yield yet. */
					sched_yield();
				}
			}

			if (!polling &&
			    ((data->options & (F_ADAPTIVE|F_FLOOD_POLL)) || data->interval)) {
				struct pollfd pset;
				pset.fd = sock->fd;
				pset.events = POLLIN;
				pset.revents = 0;
				if (poll(&pset, 1, next) < 1 ||
				    !(pset.revents&(POLLIN|POLLERR)))
					continue;
				polling = MSG_DONTWAIT;
				recv_error = pset.revents&POLLERR;
			}
		}

		for (;;) {
			struct timeval *recv_timep = NULL;
			struct timeval recv_time;
			int not_ours = 0; /* Raw socket can receive messages
					   * destined to other running pings. */

			iov.iov_len = packlen;
			memset(&msg, 0, sizeof(msg));
			msg.msg_name = addrbuf;
			msg.msg_namelen = sizeof(addrbuf);
			msg.msg_iov = &iov;
			msg.msg_iovlen = 1;
			msg.msg_control = ans_data;
			msg.msg_controllen = sizeof(ans_data);

			cc = recvmsg(sock->fd, &msg, polling);
			polling = MSG_DONTWAIT;

			if (cc < 0) {
				/* If there was a POLLERR and there is no packet
				 * on the socket, try to read the error queue.
				 * Otherwise, give up.
				 */
				if ((errno == EAGAIN && !recv_error) ||
				    errno == EINTR)
					break;
				recv_error = 0;
				if (!fset->receive_error_msg(sock, data)) {
					if (errno) {
						perror("ping: recvmsg");
						break;
					}
					not_ours = 1;
				}
			} else {

#ifdef SO_TIMESTAMP
				for (c = CMSG_FIRSTHDR(&msg); c; c = CMSG_NXTHDR(&msg, c)) {
					if (c->cmsg_level != SOL_SOCKET ||
					    c->cmsg_type != SO_TIMESTAMP)
						continue;
					if (c->cmsg_len < CMSG_LEN(sizeof(struct timeval)))
						continue;
					recv_timep = (struct timeval*)CMSG_DATA(c);
				}
#endif

				if ((data->options&F_LATENCY) || recv_timep == NULL) {
					if ((data->options&F_LATENCY) ||
					    ioctl(sock->fd, SIOCGSTAMP, &recv_time))
						gettimeofday(&recv_time, NULL);
					recv_timep = &recv_time;
				}

				not_ours = fset->parse_reply(sock, &msg, cc, addrbuf, recv_timep, data);
			}

			/* See? ... someone runs another ping on this host. */
			if (not_ours && sock->socktype == SOCK_RAW)
				fset->install_filter(sock, data);

			/* If nothing is in flight, "break" returns us to pinger. */
			if (in_flight(data) == 0)
				break;

			/* Otherwise, try to recvmsg() again. recvmsg()
			 * is nonblocking after the first iteration, so that
			 * if nothing is queued, it will receive EAGAIN
			 * and return to pinger. */
		}
	}
	data->blocking = 0;
	return finish(data);
}

int gather_statistics(__u8 *icmph, int icmplen,
		      int cc, __u16 seq, int hops,
		      int csfailed, struct timeval *tv, char *from,
		      void (*pr_reply)(__u8 *icmph, int cc), struct gbl_data *data)
{
#ifdef DEBUG
	int dupflag = 0;
#endif
	long triptime = 0;
	__u8 *ptr = icmph + icmplen;

	++data->nreceived;
	if (!csfailed)
		acknowledge(seq, data);

	if (data->timing && cc >= 8+sizeof(struct timeval)) {
		struct timeval tmp_tv;
		memcpy(&tmp_tv, ptr, sizeof(tmp_tv));

restamp:
		tvsub(tv, &tmp_tv);
		triptime = tv->tv_sec * 1000000 + tv->tv_usec;
		if (triptime < 0) {
			fprintf(stderr, "Warning: time of day goes back (%ldus), taking countermeasures.\n", triptime);
			triptime = 0;
			if (!(data->options & F_LATENCY)) {
				gettimeofday(tv, NULL);
				data->options |= F_LATENCY;
				goto restamp;
			}
		}
		if (!csfailed) {
			data->tsum += triptime;
			data->tsum2 += (long long)triptime * (long long)triptime;
			if (triptime < data->tmin)
				data->tmin = triptime;
			if (triptime > data->tmax)
				data->tmax = triptime;
			if (!data->rtt)
				data->rtt = triptime*8;
			else
				data->rtt += triptime-data->rtt/8;
			if (data->options&F_ADAPTIVE)
				update_interval(data);
		}
	}

	if (csfailed) {
		++data->nchecksum;
		--data->nreceived;
	} else if (rcvd_test(seq, data)) {
		++data->nrepeats;
		--data->nreceived;
#ifdef DEBUG
		dupflag = 1;
#endif
	} else {
		rcvd_set(seq, data);
#ifdef DEBUG
		dupflag = 0;
#endif
	}
	data->confirm = data->confirm_flag;

	if (data->options & F_QUIET)
		return 1;

	if (data->options & F_FLOOD) {
		if (!csfailed)
			write_stdout("\b \b", 3);
		else
			write_stdout("\bC", 2);
	} else {
		int i;
		__u8 *cp, *dp;
#ifdef DEBUG	
		print_timestamp(data);
		printf("%d bytes from %s:", cc, from);

		if (pr_reply)
			pr_reply(icmph, cc);

		if (hops >= 0)
			printf(" ttl=%d", hops);

		if (cc < data->datalen+8) {
			printf(" (truncated)\n");
			return 1;
		}
		if (data->timing) {
			if (triptime >= 100000)
				printf(" time=%ld ms", (triptime+500)/1000);
			else if (triptime >= 10000)
				printf(" time=%ld.%01ld ms", triptime/1000,
				       ((triptime%1000)+50)/100);
			else if (triptime >= 1000)
				printf(" time=%ld.%02ld ms", triptime/1000,
				       ((triptime%1000)+5)/10);
			else
				printf(" time=%ld.%03ld ms", triptime/1000,
				       triptime%1000);
		}
		if (dupflag)
			printf(" (DUP!)");
		if (csfailed)
			printf(" (BAD CHECKSUM!)");
#endif	
		/* check the data */
		cp = ((unsigned char*)ptr) + sizeof(struct timeval);
		dp = &data->outpack[8 + sizeof(struct timeval)];
		for (i = sizeof(struct timeval); i < data->datalen; ++i, ++cp, ++dp) {
			if (*cp != *dp) {
#ifdef DEBUG
				printf("\nwrong data byte #%d should be 0x%x but was 0x%x",
				       i, *dp, *cp);
#endif
				cp = (unsigned char*)ptr + sizeof(struct timeval);
#ifdef DEBUG
				for (i = sizeof(struct timeval); i < data->datalen; ++i, ++cp) {
					if ((i % 32) == sizeof(struct timeval))
						printf("\n#%d\t", i);
					printf("%x ", *cp);
				}
#endif
				break;
			}
		}
	}
	return 0;
}


