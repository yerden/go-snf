// Copyright 2019 Yerden Zhumabekov. All rights reserved.
//
// Use of this source code is governed by MIT license which
// can be found in the LICENSE file in the root of the source
// tree.

package snf

/*
#include <snf.h>
#include "receiver.h"
#include "filter.h"
*/
import "C"
import (
	"io"
	"sync/atomic"
	"time"
	"unsafe"
)

// RingReceiver wraps SNF's borrow-many-return-many model of packets
// retrieval, along with google's gopacket interface.
// This allows us to access low-level SNF API but maintain compatibility
// with gopacket's layers decoding abilities.
type RingReceiver struct {
	// underlying ring
	ring  C.snf_ring_t
	state *int32

	// backing reqs array
	reqs      []C.struct_snf_recv_req
	bpfResult []C.int

	// current packet index
	index int

	// packet array
	reqMany C.struct_recv_req_many
	// receive timeout
	timeoutMs C.int

	reqCurrent *RecvReq

	// last error
	err error
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
	reqs := make([]C.struct_snf_recv_req, burst)
	bpfResult := make([]C.int, burst)

	return &RingReceiver{
		ring:      r.ring,
		state:     &r.state,
		reqs:      reqs,
		bpfResult: bpfResult,
		timeoutMs: C.int(dur2ms(timeout)),
		index:     0,
		reqMany: C.struct_recv_req_many{
			reqs:       &reqs[0],
			bpf_result: &bpfResult[0],
			nreq_in:    C.int(burst),
			nreq_out:   0,
			total_len:  0},
		reqCurrent: &RecvReq{},
	}
}

// RawNext gets next packet out of ring. If true, the operation
// is a success, otherwise you should halt all actions
// on the receiver until Err() error is examined and
// needed actions are performed.
func (rr *RingReceiver) rawNext() bool {
	rm := &rr.reqMany
	for {
		if rr.index++; rr.index >= int(rm.nreq_out) {
			rr.index = 0
			if atomic.LoadInt32(rr.state) != stateOk {
				rr.err = io.EOF
				return false
			}
			// return borrowed data
			// retrieve new packets from ring
			rr.err = retErr(C.go_snf_recv_many(rr.ring, rr.timeoutMs,
				C.uintptr_t(uintptr(unsafe.Pointer(rm)))))
			if rr.err != nil {
				return false
			}
		}

		// some packets are waiting
		req := &rr.reqs[rr.index]
		if rm.fp.bf_len == 0 || rr.bpfResult[rr.index] != 0 {
			convert(rr.reqCurrent, req)
			return true
		}
	}
}

// Next gets next packet out of ring. If true, the operation
// is a success, otherwise you should halt all actions
// on the receiver until Err() error is examined and
// needed actions are performed.
func (rr *RingReceiver) Next() bool {
	return rr.rawNext()
}

// BPFResult returns the result of BPF filter calculation.
// If no filter is set, this is always zero. If a filter is set,
// the zero value would mean the packet didn't match hence
// BPFResult always would return non-zero value.
func (rr *RingReceiver) BPFResult() int {
	return int(rr.bpfResult[rr.index])
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
	return int(rr.reqMany.nreq_out) - rr.index
}

// Err returns error which was encountered during the last
// RingReceiver operation on a ring. If Next() method returned
// false, the error  may be revised here.
func (rr *RingReceiver) Err() error {
	return rr.err
}

// RingQInfo provides access the most recent Ring queue info.
func (rr *RingReceiver) RingQInfo() (q RingQInfo) {
	rm := &rr.reqMany
	q.Avail = uintptr(rm.qinfo.q_avail)
	q.Borrowed = uintptr(rm.qinfo.q_borrowed)
	q.Free = uintptr(rm.qinfo.q_free)
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
	rm := &rr.reqMany
	if atomic.LoadInt32(rr.state) != stateClosed {
		return retErr(C.snf_ring_return_many(rr.ring, rm.total_len, nil))
	}
	return nil
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
