#ifndef _RECEIVER_H_
#define _RECEIVER_H_

#include <snf.h>
int
refill(snf_ring_t ring,
       int timeout_ms,
       struct snf_recv_req *req_vector,
       int nreq_in, int *nreq_out,
       struct snf_ring_qinfo *qinfo, uint32_t * totlen)
{
	int rc;

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

	int out;
	rc = snf_ring_recv_many(ring, timeout_ms,
				req_vector, nreq_in, &out, qinfo);
	if (rc != 0)
		out = 0;

	*nreq_out = out;
	if (totlen) {
		len = 0;
		while (out)
			len += req_vector[--out].length_data;
		*totlen = len;
	}
	return rc;
}

#endif /* _RECEIVER_H_ */
