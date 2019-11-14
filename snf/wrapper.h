#ifndef _WRAPPER_H_
#define _WRAPPER_H_

static void set_rss_flags(struct snf_rss_params *rss, int flags)
{
	rss->mode = SNF_RSS_FLAGS;
	rss->params.rss_flags = flags;
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
