package snf

// #include <snf.h>
// int
// refill(snf_ring_t ring,
//        int timeout_ms,
//        struct snf_recv_req *req_vector,
//        int nreq_in, int *nreq_out,
//        struct snf_ring_qinfo *qinfo, uint32_t * totlen)
// {
//  int rc;
//  uint32_t len = totlen ? *totlen : -1;
//
//  if ((rc = snf_ring_return_many(ring, len, NULL)) != 0) {
//   if (totlen)
//    *totlen = -1;
//   return rc;
//  }
//
//  int out;
//  rc = snf_ring_recv_many(ring, timeout_ms,
//     req_vector, nreq_in, &out, qinfo);
//  if (rc != 0)
//   out = 0;
//
//  *nreq_out = out;
//  if (totlen) {
//   len = 0;
//   while (out)
//    len += req_vector[--out].length_data;
//   *totlen = len;
//  }
//  return rc;
// }
import "C"
import (
	"io"
	"sync/atomic"
	"syscall"
	"time"
)

// RawFilter interface may be applied to RingReceiver and filter
// out unneeded packets.
type RawFilter interface {
	Matches(data []byte) bool
}

// Make a RawFilter out of a function.
type RawFilterFunc func([]byte) bool

func (f RawFilterFunc) Matches(data []byte) bool {
	return f(data)
}

// RingReceiver wraps SNF's borrow-many-return-many model of packets
// retrieval, along with google's gopacket interface.
// This allows us to access low-level SNF API but maintain compatibility
// with gopacket's layers decoding abilities.
type RingReceiver struct {
	ring             C.snf_ring_t
	closed           *int32
	timeoutMs        C.int
	reqArray, reqVec []C.struct_snf_recv_req
	reqCurrent       *RecvReq
	qinfo            C.struct_snf_ring_qinfo

	// amount of data to return
	totalLen C.uint
	err      error

	filter RawFilter
}

// Create new RingReceiver.
// timeout semantics is the same as addressed in Recv() method.
// burst is the amount of packets received by underlying SNF's
// snf_ring_recv_many() function.
func (r *Ring) NewReceiver(timeout time.Duration, burst int) *RingReceiver {
	return &RingReceiver{
		ring:       r.ring,
		closed:     &r.closed,
		timeoutMs:  C.int(dur2ms(timeout)),
		reqArray:   make([]C.struct_snf_recv_req, burst),
		reqCurrent: &RecvReq{},
	}
}

// Get next packet out of ring. If true, the operation
// is a success, otherwise you should halt all actions
// on the receiver until Err() error is examined and
// needed actions are performed.
//
// Packet is returned as is with no filtering performed.
func (rr *RingReceiver) RawNext() bool {
	if len(rr.reqVec) == 0 {
		if atomic.LoadInt32(rr.closed) != 0 {
			rr.err = io.EOF
			return false
		}
		// return borrowed data
		// retrieve new packets from ring
		nreqIn, nreqOut := C.int(len(rr.reqArray)), C.int(0)
		cReqVec := (*C.struct_snf_recv_req)(&rr.reqArray[0])
		rr.err = retErr(C.refill(rr.ring, rr.timeoutMs, cReqVec,
			nreqIn, &nreqOut, &rr.qinfo, &rr.totalLen))
		if rr.err == nil {
			rr.reqVec = rr.reqArray[:nreqOut]
		} else {
			return false
		}
	}

	// some packets are waiting
	convert(rr.reqCurrent, &rr.reqVec[0])
	rr.reqVec = rr.reqVec[1:]
	return true
}

// Get next packet out of ring. If true, the operation
// is a success, otherwise you should halt all actions
// on the receiver until Err() error is examined and
// needed actions are performed.
//
// Run supplied filter on the packet.
func (rr *RingReceiver) Next() bool {
	for rr.RawNext() {
		if rr.filter == nil || rr.filter.Matches(rr.Data()) {
			return true
		}
	}

	return false
}

// Fill in the user supplied RecvReq packet descriptor.
// This will return privately held instance of RecvReq
// so make a copy if you want to retain it.
func (rr *RingReceiver) RecvReq() *RecvReq {
	return rr.reqCurrent
}

// Get retrieved packet's data. Please note that the
// underlying array of returned slice is owned by
// SNF API. Please make a copy if you want to retain it.
// The consecutive Next() call may erase this slice
// without prior notice.
func (rr *RingReceiver) Data() []byte {
	return rr.RecvReq().Pkt
}

// How many packets are cached, i.e. left to read
// without calling SNF API to retrieve new packets.
// Mostly used for testing purposes.
func (rr *RingReceiver) Avail() int {
	return len(rr.reqVec)
}

// If Next() method returned false, the error
// may be revised here.
func (rr *RingReceiver) Err() error {
	return rr.err
}

// Access the most recent Ring queue info.
func (rr *RingReceiver) RingQInfo() (q RingQInfo) {
	q.Avail = uintptr(rr.qinfo.q_avail)
	q.Borrowed = uintptr(rr.qinfo.q_borrowed)
	q.Free = uintptr(rr.qinfo.q_free)
	return
}

// Return all packets that were retrieved but not
// exposed to the user. Usually you should do this
// upon and only upon finishing working on the
// receiver.
func (rr *RingReceiver) Free() error {
	d := int32(-1)
	return retErr(C.snf_ring_return_many(rr.ring, C.uint(d), &rr.qinfo))
}

// Set RawFilter on the receiver. If set, the Next() and
// LoopNext() would not return until a packet matches
// filter.
func (rr *RingReceiver) SetRawFilter(f RawFilter) {
	rr.filter = f
}

// Similar to Next() method but this one loops if EAGAIN
// is encountered. It means that timeout hit and the port
// should be polled again.
func (rr *RingReceiver) LoopNext() bool {
	for !rr.Next() {
		if rr.Err() != syscall.Errno(syscall.EAGAIN) {
			return false
		}
	}
	return true
}
