#ifndef _RING_READER_H_
#define _RING_READER_H_

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#ifndef USE_MOCKUP
#include <snf.h>
#endif

struct ring_reader {
	snf_ring_t ringh;
	int timeout_ms;
	int nreq_out;
	int nreq_in; // allocated elements of req_vector

	struct snf_recv_req req_vector[0];
};

enum {
	RING_READER_REQ_VECTOR_OFF = offsetof(struct ring_reader, req_vector[0]),
};

/*
 * Return required size to allocate for ring_reader to contain nreq_in
 * packet descriptors.
 */
static size_t
ring_reader_size(int nreq_in)
{
	struct ring_reader *reader;
	return sizeof(*reader) + nreq_in * sizeof(reader->req_vector[0]);
}

/*
 * Return number of borrowed bytes by counting length_data from all
 * received packets in the reader.
 */
static uint32_t
ring_reader_data_qlen(struct ring_reader *reader)
{
	int i;
	uint32_t data_qlen = 0;

	for (i = 0; i < reader->nreq_out; i++) {
		data_qlen += reader->req_vector[i].length_data;
	}

	return data_qlen;
}

/*
 * Receive packets for the reader.
 *
 * 0 if received some packets.
 * non-0 if encountered some error.
 */
static int
ring_reader_recv_many(struct ring_reader *reader)
{
	if (reader->nreq_in == 1) {
		int rc = snf_ring_recv(reader->ringh, reader->timeout_ms, &reader->req_vector[0]);
		reader->nreq_out = !rc;
		return rc;
	}

	reader->nreq_out = 0;
	return snf_ring_recv_many(reader->ringh, reader->timeout_ms, reader->req_vector,
			reader->nreq_in, &reader->nreq_out, NULL);
}

/*
 * Return borrowed bytes from the reader.
 */
static int
ring_reader_return_many(struct ring_reader *reader)
{
	int rc = 0;

	if (reader->nreq_in > 1) {
		// it makes sense to return only if packets were received with
		// snf_ring_recv_many i.e. more than one descriptor is
		// supplied.
		rc = snf_ring_return_many(reader->ringh, ring_reader_data_qlen(reader), NULL);
	}

	reader->nreq_out = 0;
	return rc;
}

/*
 * Return borrowed bytes and receive new packets.
 */
static int
ring_reader_recharge(struct ring_reader *reader)
{
	int rc;

	if (reader->nreq_out > 0 && ((rc = ring_reader_return_many(reader)) != 0)) {
		return rc;
	}

	return ring_reader_recv_many(reader);
}

#endif /* _RING_READER_H_ */
