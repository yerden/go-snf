// Copyright 2019 Yerden Zhumabekov. All rights reserved.
//
// Use of this source code is governed by MIT license which
// can be found in the LICENSE file in the root of the source
// tree.

package snf

import (
	"io"
	"time"

	"golang.org/x/net/bpf"
)

// RingReceiver wraps SNF's borrow-many-return-many model of packets
// retrieval, along with google's gopacket interface.
// This allows us to access low-level SNF API but maintain compatibility
// with gopacket's layers decoding abilities.
type RingReceiver struct {
	*Ring

	reqs      []RecvReq
	bpfResult []int32
	index     int
	received  int
	timeout   time.Duration
	qinfo     RingQInfo

	filter []bpf.RawInstruction
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
	reqs := make([]RecvReq, burst)
	bpfResult := make([]int32, burst)

	return &RingReceiver{
		Ring:      r,
		reqs:      reqs,
		bpfResult: bpfResult,
		timeout:   timeout,
		index:     0,
	}
}

// RawNext gets next packet out of ring. If true, the operation
// is a success, otherwise you should halt all actions
// on the receiver until Err() error is examined and
// needed actions are performed.
func (rr *RingReceiver) reload() bool {
	if !rr.IsStateOk() {
		rr.err = io.EOF
		return false
	}
	rr.err = rr.ReturnMany(rr.reqs[:rr.received], nil)
	if rr.err != nil {
		return false
	}
	rr.received, rr.err = rr.RecvMany(rr.timeout, rr.reqs, &rr.qinfo)
	if len(rr.filter) != 0 {
		ExecuteBPF(rr.filter, rr.reqs[:rr.received], rr.bpfResult)
	}
	return rr.err == nil
}

// SetBPF sets Berkeley Packet Filter on a RingReceiver.
//
// The installed BPF will be matched across every packet received on
// it with RingReceiver.Next.
//
// If the pcap_offline_filter returns zero, RingReceiver.Next will
// silently skip this packet.
//
// SetBPF will silently replace previously set filter. You can call
// this function at any point in your program but make sure that there
// is no concurrent packet reading activity on the ring at the moment.
func (rr *RingReceiver) SetBPF(snaplen int, expr string) error {
	if insns, err := CompileBPF(snaplen, expr); err == nil {
		return rr.SetBPFInstructions(insns)
	} else {
		return err
	}
}

// SetBPFInstructions sets Berkeley Packet Filter on a RingReceiver.
// The BPF is represented as an array of instructions.
//
// If len(insns) == 0, unset the filter.
//
// See SetBPF on notes and caveats.
func (rr *RingReceiver) SetBPFInstructions(insns []bpf.RawInstruction) error {
	rr.filter = insns
	return nil
}

// RawNext gets next packet out of ring. If true, the operation
// is a success, otherwise you should halt all actions
// on the receiver until Err() error is examined and
// needed actions are performed.
func (rr *RingReceiver) rawNext() bool {
	for {
		if rr.index++; rr.index >= rr.received {
			rr.index = 0
			if !rr.reload() {
				return false
			}
		}

		if len(rr.filter) == 0 || rr.bpfResult[rr.index] != 0 {
			return true
		}
	}
}

func (rr *RingReceiver) req() *RecvReq {
	return &rr.reqs[rr.index]
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
	return rr.req()
}

// Data gets retrieved packet's data. Please note that the underlying
// array of returned slice is owned by SNF API. Please make a copy if
// you want to retain it. The consecutive Next() call may erase this
// slice without prior notice.
func (rr *RingReceiver) Data() []byte {
	return rr.req().Data()
}

// Avail shows how many packets are cached, i.e. left to read
// without calling SNF API to retrieve new packets.
// Mostly used for testing purposes.
func (rr *RingReceiver) Avail() int {
	return rr.received - rr.index
}

// Err returns error which was encountered during the last
// RingReceiver operation on a ring. If Next() method returned
// false, the error  may be revised here.
func (rr *RingReceiver) Err() error {
	return rr.err
}

// RingQInfo provides access the most recent Ring queue info.
func (rr *RingReceiver) RingQInfo() (q RingQInfo) {
	return rr.qinfo
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
	return rr.ReturnMany(rr.reqs[:rr.received], &rr.qinfo)
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
