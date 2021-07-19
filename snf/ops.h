#ifndef _GO_SNF_OPS_H_
#define _GO_SNF_OPS_H_

#include <stdint.h>
#include "wrapper.h"

struct go_snf_ops {
	// basic ops
	int (*init)(uint16_t api_version);
	int (*set_app_id)(int32_t id);
	int (*getifaddrs)(struct snf_ifaddrs ** ifaddrs_o);
	void (*freeifaddrs)(struct snf_ifaddrs * ifaddrs);
	int (*getportmask_valid)(uint32_t * mask_o, int *cnt_o);
	int (*getportmask_linkup)(uint32_t * mask_o, int *cnt_o);

	// snf handle ops
	int (*open)(uint32_t, int, const struct snf_rss_params *, int64_t, int,
		    snf_handle_t *);
	int (*open_defaults)(uint32_t portnum, snf_handle_t * devhandle);
	int (*start)(snf_handle_t);
	int (*stop)(snf_handle_t);
	int (*close)(snf_handle_t devhandle);
	int (*get_link_state)(snf_handle_t devhandle,
			      enum snf_link_state * state);

	int (*get_timesource_state)(snf_handle_t devhandle,
				    enum snf_timesource_state * state);

	int (*get_link_speed)(snf_handle_t devhandle, uint64_t * speed);

	int (*ring_open)(snf_handle_t devhandle, snf_ring_t * ringh);

	int (*ring_open_id)(snf_handle_t devhandle, int ring_id,
			    snf_ring_t * ringh);

	// ring ops
	int (*ring_recv)(snf_ring_t ringh, int timeout_ms,
			 struct snf_recv_req * recv_req);

	int (*ring_portinfo_count)(snf_ring_t ring, int *count);

	int (*ring_portinfo)(snf_ring_t ring,
			     struct snf_ring_portinfo * portinfo);

	int (*ring_recv_qinfo)(snf_ring_t ring, struct snf_ring_qinfo * qi);

	int (*ring_recv_many)(snf_ring_t ring, int timeout_ms,
			      struct snf_recv_req * req_vector, int nreq_in,
			      int *nreq_out, struct snf_ring_qinfo * qinfo);

	int (*ring_return_many)(snf_ring_t ring, uint32_t data_qlen,
				struct snf_ring_qinfo * qinfo);

	int (*ring_getstats)(snf_ring_t ringh, struct snf_ring_stats * stats);

	int (*ring_close)(snf_ring_t ringh);

	// inject ops
	int (*inject_open)(int portnum, int flags, snf_inject_t * handle);

	int (*get_injection_speed)(snf_inject_t devhandle, uint64_t * speed);

	int (*inject_send)(snf_inject_t inj, int timeout_ms, int flags,
			   const void *pkt, uint32_t length);

	int (*inject_sched)(snf_inject_t inj, int timeout_ms, int flags,
			    const void *pkt, uint32_t length,
			    uint64_t delay_ns);

	int (*inject_send_v)(snf_inject_t inj, int timeout_ms, int flags,
			     struct snf_pkt_fragment * frags_vec, int nfrags,
			     uint32_t length_hint);

	int (*inject_sched_v)(snf_inject_t inj, int timeout_ms, int flags,
			      struct snf_pkt_fragment * frags_vec, int nfrags,
			      uint32_t length_hint, uint64_t delay_ns);

	int (*inject_close)(snf_inject_t inj);

	int (*inject_getstats)(snf_inject_t inj,
			       struct snf_inject_stats * stats);

	// reflect ops
	int (*netdev_reflect_enable)(snf_handle_t hsnf,
				     snf_netdev_reflect_t * handle);

	int (*netdev_reflect)(snf_netdev_reflect_t ref_dev, const void *pkt,
			      uint32_t length);
};


#endif /* _GO_SNF_OPS_H_ */
