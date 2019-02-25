#ifndef _RECEIVER_H_
#define _RECEIVER_H_

#include <stdlib.h>
#include <errno.h>
#include <snf.h>
#include <pcap.h>

#ifndef BILLION
#define BILLION (1000 * 1000 * 1000)
#endif

struct recv_req_many {
	/* input empty reqs and bpf_result array */
	struct snf_recv_req *reqs;
	int *bpf_result;

	/* length of input array */
	int nreq_in;

	/* length of output array */
	int nreq_out;

	struct snf_ring_qinfo qinfo;
	uint32_t total_len;

	struct bpf_program fp;
};

void go_snf_recv_req_many_destroy(struct recv_req_many *reqvec)
{
	if (reqvec) {
		free(reqvec->reqs);
		free(reqvec->bpf_result);
	}
	free(reqvec);
}

int go_snf_recv_req_many_create(int nreq_in, struct recv_req_many **preqvec)
{
	typeof(*preqvec) reqvec;

	if ((reqvec = calloc(1, sizeof(*reqvec))) == NULL)
		return ENOMEM;

	typeof(reqvec->reqs) reqs;
	if ((reqs = calloc(nreq_in, sizeof(*reqs))) == NULL) {
		go_snf_recv_req_many_destroy(reqvec);
		return ENOMEM;
	}
	reqvec->reqs = reqs;

	typeof(reqvec->bpf_result) bpf_result;
	if ((bpf_result = calloc(nreq_in, sizeof(*bpf_result))) == NULL) {
		go_snf_recv_req_many_destroy(reqvec);
		return ENOMEM;
	}
	reqvec->bpf_result = bpf_result;

	reqvec->nreq_in = nreq_in;
	*preqvec = reqvec;
	return 0;
}

/*
 * Return the memory occupied by all received packets
 * back to the ring.
 */
static inline int
go_snf_return_many(snf_ring_t ring, struct recv_req_many *reqvec)
{
	int rc = snf_ring_return_many(ring, reqvec->total_len, &reqvec->qinfo);
	if (rc != 0)
		/*
		 * According to documentation, if total_len is -1,
		 * snf_ring_return_many() will free all the memory
		 * borrowed by snf_ring_recv_many()
		 */
		rc = snf_ring_return_many(ring, -1, &reqvec->qinfo);
	reqvec->total_len = 0;
	return rc;
}

/*
 * Count how many bytes have we borrowed and
 * do BPF calculations.
 */
static inline void go_snf_post_process(struct recv_req_many *reqvec)
{
	int i;
	struct bpf_program *fp = &reqvec->fp;

	for (i = 0; i < reqvec->nreq_out; i++) {
		struct snf_recv_req *req = &reqvec->reqs[i];
		/*
		 * accumulate acquired length to specify
		 * in snf_ring_return_many() during the
		 * next call
		 */
		reqvec->total_len += req->length_data;

		if (fp->bf_len && fp->bf_insns) {
			struct pcap_pkthdr hdr = {
				/* pcap_offline_filter() don't need timestamp */
				/*
				 *.ts.tv_sec = req->timestamp / BILLION,
				 *.ts.tv_usec = (req->timestamp % BILLION) / 1000,
				 */
				.caplen = req->length,
				.len = req->length,
			};
			reqvec->bpf_result[i] =
			    pcap_offline_filter(fp, &hdr, req->pkt_addr);
		}
	}
}

/*
 * Return all borrowed data from previous call and
 * retrieve new packets.
 */
static inline int
go_snf_recv_many(snf_ring_t ring, int timeout_ms, uintptr_t pReqVec)
{
	struct recv_req_many *reqvec = (typeof(reqvec)) pReqVec;
	int rc;
	int nreq_out = 1;

	if (reqvec->nreq_in == 1) {
		struct snf_recv_req *req = &reqvec->reqs[0];
		rc = snf_ring_recv(ring, timeout_ms, req);
	} else {
		if ((rc = go_snf_return_many(ring, reqvec)) == 0)
			rc = snf_ring_recv_many(ring, timeout_ms,
						reqvec->reqs, reqvec->nreq_in,
						&nreq_out, &reqvec->qinfo);
	}

	/* failed to retrieve new packets */
	if (rc != 0)
		nreq_out = 0;

	reqvec->nreq_out = nreq_out;
	go_snf_post_process(reqvec);
	return rc;
}

#endif				/* _RECEIVER_H_ */
