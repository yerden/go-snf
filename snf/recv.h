#ifndef _RECV_H_
#define _RECV_H_

#include <errno.h>

#include <pcap.h>
#include <snf.h>

#ifndef BILLION
#define BILLION (1000 * 1000 * 1000)
#endif

static inline int
ring_recv(snf_ring_t ringh,
	  int timeout_ms, struct snf_recv_req *req, struct bpf_program *fp)
{
	int rc = snf_ring_recv(ringh, timeout_ms, req);
	if (rc != 0 || fp->bf_len == 0)
		return rc;

	struct pcap_pkthdr hdr = {
		/*
		 * XXX: just filtering data
		 * why don't we save some cpu cycles and
		 * dump time setting?
		 */
		.ts.tv_sec = req->timestamp / BILLION,
		.ts.tv_usec = (req->timestamp % BILLION) / 1000,
		.caplen = req->length,
		.len = req->length,
	};

	if (pcap_offline_filter(fp, &hdr, req->pkt_addr) == 0)
		return ENOMSG;

	return 0;
}

#endif				/* _RECV_H_ */
