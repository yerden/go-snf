#ifndef _WRAPPER_H_
#define _WRAPPER_H_

#include <stdint.h>

#ifndef USE_MOCKUP
#include <snf.h>
#else
#define SNF_VERSION_API 8

#define SNF_F_PSHARED 0x1
#define SNF_F_AGGREGATE_PORTMASK 0x2
#define SNF_F_RX_DUPLICATE 0x300

typedef struct snf_handle *snf_handle_t;
typedef struct snf_ring *snf_ring_t;
typedef struct snf_inject_handle *snf_inject_t;
typedef void *snf_netdev_reflect_t;

enum snf_link_state { SNF_LINK_DOWN = 0, SNF_LINK_UP = 1 };

enum snf_timesource_state {
	SNF_TIMESOURCE_LOCAL = 0,
	SNF_TIMESOURCE_EXT_UNSYNCED,
	SNF_TIMESOURCE_EXT_SYNCED,
	SNF_TIMESOURCE_EXT_FAILED,
	SNF_TIMESOURCE_ARISTA_ACTIVE,
	SNF_TIMESOURCE_PPS,
};

enum snf_rss_params_mode {
	SNF_RSS_FLAGS = 0,
	SNF_RSS_FUNCTION = 1,
};

enum snf_rss_mode_flags {
	SNF_RSS_IP = 0x01,
	SNF_RSS_SRC_PORT = 0x10,
	SNF_RSS_DST_PORT = 0x20,
	SNF_RSS_GTP = 0x40,
	SNF_RSS_GRE = 0x80,
};

struct snf_inject_stats {
	uint64_t inj_pkt_send;
	uint64_t nic_pkt_send;
	uint64_t nic_bytes_send;
};

struct snf_ifaddrs {
	struct snf_ifaddrs *snf_ifa_next;
	const char *snf_ifa_name;
	uint32_t snf_ifa_portnum;
	int snf_ifa_maxrings;
	uint8_t snf_ifa_macaddr[6];
	uint8_t pad[2];
	int snf_ifa_maxinject;
	enum snf_link_state snf_ifa_link_state;
	uint64_t snf_ifa_link_speed;
};

struct snf_pkt_fragment {
	const void *ptr;
	uint32_t length;
};

struct snf_ring_portinfo {
	snf_ring_t ring;
	uintptr_t q_size;
	uint32_t portcnt;
	uint32_t portmask;
	uintptr_t data_addr;
	uintptr_t data_size;
};

struct snf_recv_req {
	void *pkt_addr;
	uint32_t length;
	uint64_t timestamp;
	uint32_t portnum;
	uint32_t length_data;
	uint32_t hw_hash;
};

struct snf_ring_qinfo {
	uintptr_t q_avail;
	uintptr_t q_borrowed;
	uintptr_t q_free;
};

struct snf_ring_stats {
	uint64_t nic_pkt_recv;
	uint64_t nic_pkt_overflow;
	uint64_t nic_pkt_bad;
	uint64_t ring_pkt_recv;
	uint64_t ring_pkt_overflow;
	uint64_t nic_bytes_recv;
	uint64_t snf_pkt_overflow;
	uint64_t nic_pkt_dropped;
};

struct snf_rss_mode_function {
	int (*rss_hash_fn)(struct snf_recv_req * r, void *context,
			   uint32_t * hashval);

	void *rss_context;
};

struct snf_rss_params {
	enum snf_rss_params_mode mode;
	union {
		enum snf_rss_mode_flags rss_flags;
		struct snf_rss_mode_function rss_function;
	} params;
};

#endif

static void add_rss_flags(struct snf_rss_params *rss, int flags)
{
	rss->mode = SNF_RSS_FLAGS;
	rss->params.rss_flags |= flags;
}

typedef int (rss_hash_fn) (struct snf_recv_req *, void *, uint32_t *);

static void set_rss_func(struct snf_rss_params *rss, rss_hash_fn * fn,
			 void *ctx)
{
	rss->mode = SNF_RSS_FUNCTION;
	rss->params.rss_function.rss_hash_fn = fn;
	rss->params.rss_function.rss_context = ctx;
}

/*
 * Encompass at least 12 bytes of storage + return int code.
 * Should be 16 bytes on amd64.
 */
struct compound_int {
	union {
		char data[12];
		uint64_t u64;
		int i[3];
		unsigned int u[3];
		uintptr_t uptr;
	};
	int rc;
};

static struct compound_int ring_recv_many(snf_ring_t ring, int timeout_ms,
					  struct snf_recv_req *req_vector,
					  int nreq_in,
					  struct snf_ring_qinfo *qinfo)
{
	struct compound_int out;
	out.rc = snf_ring_recv_many(ring, timeout_ms, req_vector, nreq_in,
				    (int *)&out, qinfo);
	return out;
}

static struct compound_int get_link_state(snf_handle_t h)
{
	struct compound_int out;
	out.rc = snf_get_link_state(h, (enum snf_link_state *)&out);
	return out;
}

static struct compound_int get_link_speed(snf_handle_t h)
{
	struct compound_int out;
	out.rc = snf_get_link_speed(h, (uint64_t *) & out);
	return out;
}

static struct compound_int get_timesource_state(snf_handle_t h)
{
	struct compound_int out;
	out.rc = snf_get_timesource_state(h, (enum snf_timesource_state *)&out);
	return out;
}

#endif
/* _WRAPPER_H_ */
