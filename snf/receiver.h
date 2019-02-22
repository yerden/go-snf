#ifndef _RECEIVER_H_
#define _RECEIVER_H_

#include <errno.h>
#include <snf.h>
#include <pcap.h>

#ifndef BILLION
#define BILLION (1000 * 1000 * 1000)
#endif

int
recv_return_many(snf_ring_t ring,
		 int timeout_ms,
		 struct snf_recv_req *req_vector,
		 int nreq_in, int *nreq_out,
		 struct snf_ring_qinfo *qinfo, uint32_t * totlen,
		 struct bpf_program *fp)
{
	int rc;
	//struct bpf_program *fp = (struct bpf_program *)fp_p;

	if (nreq_in == 1) {
		rc = snf_ring_recv(ring, timeout_ms, req_vector);
		*nreq_out = (rc == 0);
		return rc;
	}

	uint32_t len = totlen ? *totlen : -1;

	if ((rc = snf_ring_return_many(ring, len, NULL)) != 0) {
		if (totlen)
			*totlen = -1;
		return rc;
	}

	int i;
	int out;
	rc = snf_ring_recv_many(ring, timeout_ms,
				req_vector, nreq_in, &out, qinfo);
	if (rc != 0)
		out = 0;

	*nreq_out = out;
	len = 0;
	for (i = 0; i < out; i++) {
		struct snf_recv_req *req = &req_vector[i];
		/*
		 * accumulate acquired length to specify
		 * in snf_ring_return_many() during the
		 * next call
		 */
		len += req->length_data;

		if (fp) {
			/* we have filter set */
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
				/*
				 * mimic the BPF behaviour
				 * since the packet did not pass the filter
				 * pretend that it's length is zero to
				 * signal that we should skip that packet
				 */
				req->length = 0;
		}
	}

	if (totlen)
		*totlen = len;

	return rc;
}

#endif				/* _RECEIVER_H_ */
