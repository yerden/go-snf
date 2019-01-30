package snf

// #include <snf.h>
// int refill(
//   snf_ring_t ring,
//   int timeout_ms,
//   struct snf_recv_req *req_vector,
//   int nreq_in, int *nreq_out,
//   struct snf_ring_qinfo *qinfo, uint32_t *totlen) {
//  int rc;
//  uint32_t len = *totlen;
//  if (len) {
//   if ((rc = snf_ring_return_many(ring, len, NULL)) != 0) {
//    return rc;
//   }
//  }
//
//  len = 0;
//  int out;
//  rc = snf_ring_recv_many(ring, timeout_ms,
//    req_vector, nreq_in, &out, qinfo);
//  if (rc != 0) {
//   return rc;
//  }
//
//  for (rc = 0; rc < out; rc++) {
//   len += req_vector[rc].length_data;
//  }
//  *nreq_out = out;
//  *totlen = len;
//
//  return 0;
// }
import "C"
import (
	"syscall"
	"time"

	"github.com/google/gopacket"
)

// Filter interface may be applied to RingReceiver and filter
// out unneeded packets. This interface is satisfied by
// gopacket/pcap BPF object.
type Filter interface {
	Matches(ci gopacket.CaptureInfo, data []byte) bool
}

// RingReceiver wraps SNF's borrow-many-return-many model of packets
// retrieval, along with google's gopacket interface.
// This allows us to access low-level SNF API but maintain compatibility
// with gopacket's layers decoding abilities.
type RingReceiver struct {
	ring             C.snf_ring_t
	timeoutMs        C.int
	reqArray, reqVec []C.struct_snf_recv_req
	reqCurrent       *C.struct_snf_recv_req
	qinfo            C.struct_snf_ring_qinfo

	// amount of data to return
	totalLen C.uint
	err      error

	ci     gopacket.CaptureInfo
	filter Filter
}

// Create new RingReceiver.
// timeout semantics is the same as addressed in Recv() method.
// burst is the amount of packets received by underlying SNF's
// snf_ring_recv_many() function.
func (r *Ring) NewReceiver(timeout time.Duration, burst int) *RingReceiver {
	return &RingReceiver{
		ring:      r.ring,
		timeoutMs: C.int(timeout.Nanoseconds() / 1000000),
		reqArray:  make([]C.struct_snf_recv_req, burst),
	}
}

func (rr *RingReceiver) getNext() bool {
	if len(rr.reqVec) == 0 {
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
	rr.reqCurrent = &rr.reqVec[0]
	rr.reqVec = rr.reqVec[1:]
	rr.makeCaptureInfo()
	return true
}

// Get next packet out of ring. If true, the operation
// is a success, otherwise you should halt all actions
// on the receiver until Err() error is examined and
// needed actions are performed.
func (rr *RingReceiver) Next() bool {
	for rr.getNext() {
		if rr.filter == nil || rr.filter.Matches(rr.CaptureInfo(), rr.Data()) {
			return true
		}
	}

	return false
}

// Fill in the user supplied RecvReq packet descriptor.
func (rr *RingReceiver) RecvReq(req *RecvReq) {
	convert(req, rr.reqCurrent)
}

// Get retrieved packet's data. Please note that the
// underlying array of returned slice is owned by
// SNF API. Please make a copy if you want to retain it.
// The consecutive Next() call may erase this slice
// without prior notice.
func (rr *RingReceiver) Data() []byte {
	return getData(rr.reqCurrent)
}

// How many packets are cached, i.e. left to read
// without calling SNF API to retrieve new packets.
// Mostly used for testing purposes.
func (rr *RingReceiver) Avail() int {
	return len(rr.reqVec)
}

func (rr *RingReceiver) makeCaptureInfo() {
	rc := rr.reqCurrent
	rr.ci.CaptureLength = int(rc.length)
	rr.ci.InterfaceIndex = int(rc.portnum)
	rr.ci.Length = rr.ci.CaptureLength
	rr.ci.Timestamp = time.Unix(0, int64(rc.timestamp))
	return
}

// Return gopacket.CaptureInfo for retrieved packet.
func (rr *RingReceiver) CaptureInfo() (ci gopacket.CaptureInfo) {
	return rr.ci
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
	if sz := rr.totalLen; sz > 0 {
		rr.totalLen = 0
		return retErr(C.snf_ring_return_many(rr.ring, sz, &rr.qinfo))
	}
	return nil
}

// Set Filter on the receiver. If set, the Next() and
// LoopNext() would not return until a packet matches
// filter. Hint: BPF filter from gopacket package
// satisfies Filter interface.
func (rr *RingReceiver) SetFilter(f Filter) {
	rr.filter = f
}

var _ gopacket.ZeroCopyPacketDataSource = (*RingReceiver)(nil)

// Another packet retrieval capability which satisfies
// gopacket.ZeroCopyPacketDataSource interface.
func (rr *RingReceiver) ZeroCopyReadPacketData() (data []byte, ci gopacket.CaptureInfo, err error) {
	if !rr.LoopNext() {
		err = rr.Err()
	} else {
		data = rr.Data()
		ci = rr.CaptureInfo()
	}

	return
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
