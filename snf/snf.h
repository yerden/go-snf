#ifndef _SNF_H_
#define _SNF_H_

#include <snf.h>
#include "ops.h"

struct go_snf_ops snf_ops = {
	// basic ops
	.init = snf_init,
	.set_app_id = snf_set_app_id,
	.getifaddrs = snf_getifaddrs,
	.freeifaddrs = snf_freeifaddrs,
	.getportmask_valid = snf_getportmask_valid,
	.getportmask_linkup = snf_getportmask_linkup,

	// snf handle ops
	.open = snf_open,
	.open_defaults = snf_open_defaults,
	.start = snf_start,
	.stop = snf_stop,
	.close = snf_close,
	.get_link_state = snf_get_link_state,

	.get_timesource_state = snf_get_timesource_state,
	.get_link_speed = snf_get_link_speed,
	.ring_open = snf_ring_open,
	.ring_open_id = snf_ring_open_id,

	// ring ops
	.ring_recv = snf_ring_recv,
	.ring_portinfo_count = snf_ring_portinfo_count,
	.ring_portinfo = snf_ring_portinfo,
	.ring_recv_qinfo = snf_ring_recv_qinfo,
	.ring_recv_many = snf_ring_recv_many,
	.ring_return_many = snf_ring_return_many,
	.ring_getstats = snf_ring_getstats,
	.ring_close = snf_ring_close,

	// inject ops
	.inject_open = snf_inject_open,
	.get_injection_speed = snf_get_injection_speed,
	.inject_send = snf_inject_send,
	.inject_sched = snf_inject_sched,
	.inject_send_v = snf_inject_send_v,
	.inject_sched_v = snf_inject_sched_v,
	.inject_close = snf_inject_close,
	.inject_getstats = snf_inject_getstats,

	// reflect ops
	.netdev_reflect_enable = snf_netdev_reflect_enable,
	.netdev_reflect = snf_netdev_reflect,
};

#endif /* _SNF_H_ */
