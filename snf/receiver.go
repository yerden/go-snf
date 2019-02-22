// Copyright 2019 Yerden Zhumabekov. All rights reserved.
//
// Use of this source code is governed by MIT license which
// can be found in the LICENSE file in the root of the source
// tree.

package snf

// #include <snf.h>
// #include "receiver.h"
import "C"
import (
	"io"
	"sync/atomic"
	"time"
)

// RawFilter interface may be applied to RingReceiver and filter
// out unneeded packets.
type RawFilter interface {
	Matches(data []byte) bool
}

// RawFilterFunc implements RawFilter interface.
type RawFilterFunc func([]byte) bool

// Matches returns true if packet matches Filter condition.
func (f RawFilterFunc) Matches(data []byte) bool {
	return f(data)
}

// RingReceiver wraps SNF's borrow-many-return-many model of packets
// retrieval, along with google's gopacket interface.
// This allows us to access low-level SNF API but maintain compatibility
// with gopacket's layers decoding abilities.
type RingReceiver struct {
	ring             C.snf_ring_t
	fp               *C.struct_bpf_program
	state            *int32
	timeoutMs        C.int
	reqArray, reqVec []C.struct_snf_recv_req
	reqCurrent       *RecvReq
	qinfo            C.struct_snf_ring_qinfo

	// amount of data to return
	totalLen C.uint
	err      error

	filter RawFilter
}

// NewReceiver creates new RingReceiver.
// timeout semantics is the same as addressed in Recv() method.
// burst is the amount of packets received by underlying SNF's
// snf_ring_recv_many() function.
//
// Warning: please be aware that snf_ring_recv_many() doesn't
// work with aggregated rings (flag AggregatePortMask must be off).
// If you want to use AggregatePortMask feature, please use
// burst==1. In that case, RingReceiver will utilize snf_ring_recv()
// which works in either cases.
func (r *Ring) NewReceiver(timeout time.Duration, burst int) *RingReceiver {
	return &RingReceiver{
		ring:       r.ring,
		fp:         r.fp,
		state:      &r.state,
		timeoutMs:  C.int(dur2ms(timeout)),
		reqArray:   make([]C.struct_snf_recv_req, burst),
		reqCurrent: &RecvReq{},
	}
}

// RawNext gets next packet out of ring. If true, the operation
// is a success, otherwise you should halt all actions
// on the receiver until Err() error is examined and
// needed actions are performed.
//
// Packet is returned as is with no filtering performed.
func (rr *RingReceiver) RawNext() bool {
	for {
		if len(rr.reqVec) == 0 {
			if atomic.LoadInt32(rr.state) != stateOk {
				rr.err = io.EOF
				return false
			}
			// return borrowed data
			// retrieve new packets from ring
			nreqIn, nreqOut := C.int(len(rr.reqArray)), C.int(0)
			cReqVec := (*C.struct_snf_recv_req)(&rr.reqArray[0])

			// we're doing some nasty-casty thing here
			// since fp is allocated on heap, it will not
			// be cleared once we call cgo.
			rr.err = retErr(C.recv_return_many(rr.ring, rr.timeoutMs, cReqVec,
				nreqIn, &nreqOut, &rr.qinfo, &rr.totalLen, rr.fp))
			if rr.err == nil {
				rr.reqVec = rr.reqArray[:nreqOut]
			} else {
				return false
			}
		}

		// some packets are waiting
		req := &rr.reqVec[0]
		rr.reqVec = rr.reqVec[1:]

		if req.length != 0 {
			convert(rr.reqCurrent, req)
			return true
		}
	}
}

// Next gets next packet out of ring. If true, the operation
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

// RecvReq returns current packet descriptor. This descriptor
// points to privately held instance of RecvReq so make a copy
// if you want to retain it.
func (rr *RingReceiver) RecvReq() *RecvReq {
	return rr.reqCurrent
}

// Data gets retrieved packet's data. Please note that the
// underlying array of returned slice is owned by
// SNF API. Please make a copy if you want to retain it.
// The consecutive Next() call may erase this slice
// without prior notice.
func (rr *RingReceiver) Data() []byte {
	return rr.RecvReq().Pkt
}

// Avail shows how many packets are cached, i.e. left to read
// without calling SNF API to retrieve new packets.
// Mostly used for testing purposes.
func (rr *RingReceiver) Avail() int {
	return len(rr.reqVec)
}

// Err returns error which was encountered during the last
// RingReceiver operation on a ring. If Next() method returned
// false, the error  may be revised here.
func (rr *RingReceiver) Err() error {
	return rr.err
}

// RingQInfo provides access the most recent Ring queue info.
func (rr *RingReceiver) RingQInfo() (q RingQInfo) {
	q.Avail = uintptr(rr.qinfo.q_avail)
	q.Borrowed = uintptr(rr.qinfo.q_borrowed)
	q.Free = uintptr(rr.qinfo.q_free)
	return
}

// Free returns all packets that were retrieved but not
// exposed to the user. Usually you should do this
// upon and only upon finishing working on the
// receiver.
//
// Note that now, running this function is redundant
// if you don't intend to use underlying ring further
// until it Close()-s. Nevertheless, the use of this
// function is encouraged anyway as a matter of good
// code style.
func (rr *RingReceiver) Free() error {
	if atomic.LoadInt32(rr.state) != stateClosed {
		return retErr(C.snf_ring_return_many(rr.ring, rr.totalLen, &rr.qinfo))
	}
	return nil
}

// SetRawFilter sets RawFilter on the receiver. If set, the Next() and
// LoopNext() would not return until a packet matches
// filter.
func (rr *RingReceiver) SetRawFilter(f RawFilter) {
	rr.filter = f
}

// LoopNext is similar to Next() method but this one loops if EAGAIN
// is encountered. It means that timeout hit and the port
// should be polled again.
func (rr *RingReceiver) LoopNext() bool {
	for !rr.Next() {
		if !IsEagain(rr.Err()) {
			return false
		}
	}
	return true
}
