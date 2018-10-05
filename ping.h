#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <poll.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <linux/types.h>
#include <linux/sockios.h>
#include <sys/file.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/uio.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <setjmp.h>
#include <netinet/icmp6.h>
#include <asm/byteorder.h>
#include <sched.h>
#include <math.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <linux/filter.h>
#include <resolv.h>
#include <locale.h>

#define getaddrinfo_flags (AI_CANONNAME)
#define getnameinfo_flags 0

#ifndef WITHOUT_IFADDRS
#include <ifaddrs.h>
#endif

#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/types.h>
#include <linux/errqueue.h>

#ifndef SCOPE_DELIMITER
#define SCOPE_DELIMITER '%'
#endif

#define	DEFDATALEN	(64 - 8)	/* default data length */

#define	MAXWAIT		10		/* max seconds to wait for response */
#define MININTERVAL	10		/* Minimal interpacket gap */
#define MINUSERINTERVAL	200		/* Minimal allowed interval for non-root */

#define SCHINT(a)	(((a) <= MININTERVAL) ? MININTERVAL : (a))

/* various options */
//extern int options;
#define	F_FLOOD		0x001
#define	F_INTERVAL	0x002
#define	F_NUMERIC	0x004
#define	F_PINGFILLED	0x008
#define	F_QUIET		0x010
#define	F_RROUTE	0x020
#define	F_SO_DEBUG	0x040
#define	F_SO_DONTROUTE	0x080
#define	F_VERBOSE	0x100
#define	F_TIMESTAMP	0x200
#define	F_SOURCEROUTE	0x400
#define	F_FLOOD_POLL	0x800
#define	F_LATENCY	0x1000
#define	F_AUDIBLE	0x2000
#define	F_ADAPTIVE	0x4000
#define	F_STRICTSOURCE	0x8000
#define F_NOLOOP	0x10000
#define F_TTL		0x20000
#define F_MARK		0x40000
#define F_PTIMEOFDAY	0x80000
#define F_OUTSTANDING	0x100000
#define F_FLOWINFO	0x200000
#define F_TCLASS	0x400000

/*
 * MAX_DUP_CHK is the number of bits in received table, i.e. the maximum
 * number of received sequence numbers we can keep track of.
 */
#define	MAX_DUP_CHK	0x10000

#if defined(__WORDSIZE) && __WORDSIZE == 64
# define USE_BITMAP64
#endif

#ifdef USE_BITMAP64
typedef __u64	bitmap_t;
# define BITMAP_SHIFT	6
#else
typedef __u32	bitmap_t;
# define BITMAP_SHIFT	5
#endif

#if ((MAX_DUP_CHK >> (BITMAP_SHIFT + 3)) << (BITMAP_SHIFT + 3)) != MAX_DUP_CHK
# error Please MAX_DUP_CHK and/or BITMAP_SHIFT
#endif

struct rcvd_table {
	bitmap_t bitmap[MAX_DUP_CHK / (sizeof(bitmap_t) * 8)];
};

#define	MAXPACKET	128000		/* max packet size */
//#define DEBUG

struct gbl_data {
	int blocking; // support threadsafe

	struct rcvd_table rcvd_tbl;

	int options;
	int datalen;
	char *hostname;
	int uid;
	uid_t euid;
	int ident;			/* process id to identify our packets */

	int sndbuf;
	int ttl;

	long npackets;			/* max packets to transmit */
	long nreceived;			/* # of packets we got back */
	long nrepeats;			/* number of duplicates */
	long ntransmitted;		/* sequence # for outbound packets = #sent */
	long nchecksum;			/* replies with bad checksum */
	long nerrors;			/* icmp errors */
	int interval;			/* interval between packets (msec) */
	int preload;
	int deadline;			/* time to die */
	int lingertime;
	struct timeval start_time, cur_time;
	volatile int exiting;
	volatile int status_snapshot;
	int confirm;
	int confirm_flag;
	char *device;
	int pmtudisc;

	volatile int in_pr_addr;		/* pr_addr() is executing */
	jmp_buf pr_addr_jmp;

	/* timing */
	int timing;			/* flag to do timing */
	long tmin;			/* minimum round trip time */
	long tmax;			/* maximum round trip time */
	long long tsum;			/* sum of all times, for doing average */
	long long tsum2;
	int rtt;
	int rtt_addend;
	__u16 acked;
	int pipesize;
	int mark;
	unsigned char outpack[MAXPACKET];

	int screen_width;
	int ts_type;
	int broadcast_pings;
	struct sockaddr_in whereto;	/* who to ping */
	struct sockaddr_in source;
};


#define	A(bit)	(data->rcvd_tbl.bitmap[(bit) >> BITMAP_SHIFT])	/* identify word in array */
#define	B(bit)	(((bitmap_t)1) << ((bit) & ((1 << BITMAP_SHIFT) - 1)))	/* identify bit in word */

static inline void rcvd_set(__u16 seq, struct gbl_data *data)
{
	unsigned bit = seq % MAX_DUP_CHK;
	A(bit) |= B(bit);
}

static inline void rcvd_clear(__u16 seq, struct gbl_data *data)
{
	unsigned bit = seq % MAX_DUP_CHK;
	A(bit) &= ~B(bit);
}

static inline bitmap_t rcvd_test(__u16 seq, struct gbl_data *data)
{
	unsigned bit = seq % MAX_DUP_CHK;
	return A(bit) & B(bit);
}


#ifndef MSG_CONFIRM
#define MSG_CONFIRM 0
#endif

extern struct gbl_data data;

/*
 * Write to stdout
 */
static inline void write_stdout(const char *str, size_t len)
{
	size_t o = 0;
	ssize_t cc;
	do {
		cc = write(STDOUT_FILENO, str + o, len - o);
		o += cc;
	} while (len > o || cc < 0);
}

/*
 * tvsub --
 *	Subtract 2 timeval structs:  out = out - in.  Out is assumed to
 * be >= in.
 */
static inline void tvsub(struct timeval *out, struct timeval *in)
{
	if ((out->tv_usec -= in->tv_usec) < 0) {
		--out->tv_sec;
		out->tv_usec += 1000000;
	}
	out->tv_sec -= in->tv_sec;
}

static inline void set_signal(int signo, void (*handler)(int))
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));

	sa.sa_handler = (void (*)(int))handler;
#ifdef SA_INTERRUPT
	sa.sa_flags = SA_INTERRUPT;
#endif
	sigaction(signo, &sa, NULL);
}

extern int __schedule_exit(int next, struct gbl_data *data);

static inline int schedule_exit(int next, struct gbl_data *data)
{
	if (data->npackets && data->ntransmitted >= data->npackets && !data->deadline)
		next = __schedule_exit(next, data);
	return next;
}

static inline int in_flight(struct gbl_data *data)
{
	__u16 diff = (__u16)data->ntransmitted - data->acked;
	return (diff<=0x7FFF) ? diff : (data->ntransmitted - data->nreceived - data->nerrors);
}

static inline void acknowledge(__u16 seq, struct gbl_data *data)
{
	__u16 diff = (__u16)data->ntransmitted - seq;
	if (diff <= 0x7FFF) {
		if ((int)diff+1 > data->pipesize)
			data->pipesize = (int)diff+1;
		if ((__s16)(seq - data->acked) > 0 ||
		    (__u16)data->ntransmitted - data->acked > 0x7FFF)
			data->acked = seq;
	}
}

static inline void advance_ntransmitted(struct gbl_data *data)
{
	data->ntransmitted++;
	/* Invalidate acked, if 16 bit seq overflows. */
	if ((__u16)data->ntransmitted - data->acked > 0x7FFF)
		data->acked = (__u16)data->ntransmitted + 1;
}

typedef struct socket_st {
	int fd;
	int socktype;
} socket_st;

typedef struct ping_func_set_st {
	int (*send_probe)(socket_st *, void *packet, unsigned packet_size, struct gbl_data *data);
	int (*receive_error_msg)(socket_st *sock, struct gbl_data *data);
	int (*parse_reply)(socket_st *, struct msghdr *msg, int len, void *addr, struct timeval *, struct gbl_data *data);
	void (*install_filter)(socket_st *, struct gbl_data *);
} ping_func_set_st;

int ping4_api(char *target);

