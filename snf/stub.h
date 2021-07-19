#include <errno.h>

#include "ops.h"

static int stub_init(uint16_t api_version)
{
	return ENOTSUP;
}

static int stub_set_app_id(int32_t id)
{
	return ENOTSUP;
}

static int stub_getifaddrs(struct snf_ifaddrs **ifaddrs_o)
{
	return ENOTSUP;
}

static void stub_freeifaddrs(struct snf_ifaddrs *ifaddrs)
{
}

static int stub_getportmask_valid(uint32_t * mask_o, int *cnt_o)
{
	return ENOTSUP;
}

static int stub_getportmask_linkup(uint32_t * mask_o, int *cnt_o)
{
	return ENOTSUP;
}

static int stub_open(uint32_t portnum,
		    int num_rings,
		    const struct snf_rss_params *rss_params,
		    int64_t dataring_sz, int flags, snf_handle_t * devhandle)
{
	return ENOTSUP;
}

static int stub_open_defaults(uint32_t portnum, snf_handle_t * devhandle)
{
	return ENOTSUP;
}

static int stub_start(snf_handle_t devhandle)
{
	return ENOTSUP;
}

static int stub_stop(snf_handle_t devhandle)
{
	return ENOTSUP;
}

static int stub_get_link_state(snf_handle_t devhandle,
			      enum snf_link_state *state)
{
	return ENOTSUP;
}

static int stub_get_timesource_state(snf_handle_t devhandle,
				    enum snf_timesource_state *state)
{
	return ENOTSUP;
}

static int stub_get_link_speed(snf_handle_t devhandle, uint64_t * speed)
{
	return ENOTSUP;
}

static int stub_close(snf_handle_t devhandle)
{
	return ENOTSUP;
}

static int stub_ring_open(snf_handle_t devhandle, snf_ring_t * ringh)
{
	return ENOTSUP;
}

static int stub_ring_open_id(snf_handle_t devhandle, int ring_id,
			    snf_ring_t * ringh)
{
	return ENOTSUP;
}

static int stub_ring_close(snf_ring_t ringh)
{
	return ENOTSUP;
}

static int stub_ring_recv(snf_ring_t ringh, int timeout_ms,
			 struct snf_recv_req *recv_req)
{
	return ENOTSUP;
}

static int stub_ring_portinfo_count(snf_ring_t ring, int *count)
{
	return ENOTSUP;
}

static int stub_ring_portinfo(snf_ring_t ring,
			     struct snf_ring_portinfo *portinfo)
{
	return ENOTSUP;
}

static int stub_ring_recv_qinfo(snf_ring_t ring, struct snf_ring_qinfo *qi)
{
	return ENOTSUP;
}

static int stub_ring_recv_many(snf_ring_t ring, int timeout_ms,
			      struct snf_recv_req *req_vector, int nreq_in,
			      int *nreq_out, struct snf_ring_qinfo *qinfo)
{
	return ENOTSUP;
}

static int stub_ring_return_many(snf_ring_t ring, uint32_t data_qlen,
				struct snf_ring_qinfo *qinfo)
{
	return ENOTSUP;
}

static int stub_ring_getstats(snf_ring_t ringh, struct snf_ring_stats *stats)
{
	return ENOTSUP;
}

static int stub_inject_open(int portnum, int flags, snf_inject_t * handle)
{
	return ENOTSUP;
}

static int stub_get_injection_speed(snf_inject_t devhandle, uint64_t * speed)
{
	return ENOTSUP;
}

static int stub_inject_send(snf_inject_t inj, int timeout_ms, int flags,
			   const void *pkt, uint32_t length)
{
	return ENOTSUP;
}

static int stub_inject_sched(snf_inject_t inj, int timeout_ms, int flags,
			    const void *pkt, uint32_t length, uint64_t delay_ns)
{
	return ENOTSUP;
}

static int stub_inject_send_v(snf_inject_t inj, int timeout_ms, int flags,
			     struct snf_pkt_fragment *frags_vec, int nfrags,
			     uint32_t length_hint)
{
	return ENOTSUP;
}

static int stub_inject_sched_v(snf_inject_t inj, int timeout_ms, int flags,
			      struct snf_pkt_fragment *frags_vec, int nfrags,
			      uint32_t length_hint, uint64_t delay_ns)
{
	return ENOTSUP;
}

static int stub_inject_close(snf_inject_t inj)
{
	return ENOTSUP;
}

static int stub_inject_getstats(snf_inject_t inj, struct snf_inject_stats *stats)
{
	return ENOTSUP;
}

static int stub_netdev_reflect_enable(snf_handle_t hsnf,
				     snf_netdev_reflect_t * handle)
{
	return ENOTSUP;
}

static int stub_netdev_reflect(snf_netdev_reflect_t ref_dev, const void *pkt,
			      uint32_t length)
{
	return ENOTSUP;
}

struct go_snf_ops stub_ops = {
	// basic ops
	.init = stub_init,
	.set_app_id = stub_set_app_id,
	.getifaddrs = stub_getifaddrs,
	.freeifaddrs = stub_freeifaddrs,
	.getportmask_valid = stub_getportmask_valid,
	.getportmask_linkup = stub_getportmask_linkup,

	// snf handle ops
	.open = stub_open,
	.open_defaults = stub_open_defaults,
	.start = stub_start,
	.stop = stub_stop,
	.close = stub_close,
	.get_link_state = stub_get_link_state,

	.get_timesource_state = stub_get_timesource_state,
	.get_link_speed = stub_get_link_speed,
	.ring_open = stub_ring_open,
	.ring_open_id = stub_ring_open_id,

	// ring ops
	.ring_recv = stub_ring_recv,
	.ring_portinfo_count = stub_ring_portinfo_count,
	.ring_portinfo = stub_ring_portinfo,
	.ring_recv_qinfo = stub_ring_recv_qinfo,
	.ring_recv_many = stub_ring_recv_many,
	.ring_return_many = stub_ring_return_many,
	.ring_getstats = stub_ring_getstats,
	.ring_close = stub_ring_close,

	// inject ops
	.inject_open = stub_inject_open,
	.get_injection_speed = stub_get_injection_speed,
	.inject_send = stub_inject_send,
	.inject_sched = stub_inject_sched,
	.inject_send_v = stub_inject_send_v,
	.inject_sched_v = stub_inject_sched_v,
	.inject_close = stub_inject_close,
	.inject_getstats = stub_inject_getstats,

	// reflect ops
	.netdev_reflect_enable = stub_netdev_reflect_enable,
	.netdev_reflect = stub_netdev_reflect,
};
