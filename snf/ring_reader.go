// Copyright 2019 Yerden Zhumabekov. All rights reserved.
//
// Use of this source code is governed by MIT license which
// can be found in the LICENSE file in the root of the source
// tree.

package snf

import (
	"fmt"
	"os"
	"syscall"
	"time"
)

// RingReader wraps SNF's borrow-many-return-many model of packets
// retrieval, along with google's gopacket interface. This allows us
// to access low-level SNF API but maintain compatibility with
// gopacket's layers decoding abilities.
type RingReader struct {
	*Ring

	sigCh    <-chan os.Signal
	reqs     []RecvReq
	index    int
	received int
	timeout  time.Duration
	qinfo    RingQInfo

	// last error
	err error
}

// NewReader creates new RingReader.  timeout semantics is the same as
// addressed in Recv() method.  burst is the amount of packets
// received by underlying SNF's snf_ring_recv_many() function.
//
// Warning: please be aware that snf_ring_recv_many() doesn't work
// with aggregated rings (flag AggregatePortMask must be off).  If you
// want to use AggregatePortMask feature, please use burst==1. In that
// case, RingReader will utilize snf_ring_recv() which works in both
// cases.
func NewReader(r *Ring, timeout time.Duration, burst int) *RingReader {
	return &RingReader{
		Ring:    r,
		reqs:    make([]RecvReq, burst),
		timeout: timeout,
		index:   0,
	}
}

// NotifyWith installs signal notification channel which is presumably
// registered via signal.Notify.
func (rr *RingReader) NotifyWith(ch <-chan os.Signal) {
	rr.sigCh = ch
}

func (rr *RingReader) checkSignal() error {
	if ch := rr.sigCh; ch != nil {
		select {
		case sig := <-ch:
			return fmt.Errorf("caught: %v", sig)
		default:
		}
	}
	return nil
}

// RawNext gets next packet out of ring. If true, the operation is a
// success, otherwise you should halt all actions on the receiver
// until Err() error is examined and needed actions are performed.
func (rr *RingReader) reload() bool {
	if rr.err = rr.checkSignal(); rr.err != nil {
		return false
	}
	rr.err = rr.ReturnMany(rr.reqs[:rr.received], nil)
	if rr.err != nil {
		return false
	}
	rr.received, rr.err = rr.RecvMany(rr.timeout, rr.reqs, &rr.qinfo)
	return rr.err == nil
}

func (rr *RingReader) reloadOne() bool {
	if rr.err = rr.checkSignal(); rr.err != nil {
		return false
	}
	rr.err = rr.Recv(rr.timeout, &rr.reqs[0])
	rr.received = 1
	return rr.err == nil
}

// RawNext gets next packet out of ring. If true, the operation is a
// success, otherwise you should halt all actions on the receiver
// until Err() error is examined and needed actions are performed.
func (rr *RingReader) rawNext() bool {
	for {
		if rr.index++; rr.index >= rr.received {
			rr.index = 0
			var ok bool
			if len(rr.reqs) == 1 {
				ok = rr.reloadOne()
			} else {
				ok = rr.reload()
			}
			if !ok {
				return false
			}
		}

		return true
	}
}

func (rr *RingReader) req() *RecvReq {
	return &rr.reqs[rr.index]
}

// Next gets next packet out of ring. If true, the operation is a
// success, otherwise you should halt all actions on the receiver
// until Err() error is examined and needed actions are performed.
func (rr *RingReader) Next() bool {
	return rr.rawNext()
}

// RecvReq returns current packet descriptor. This descriptor points
// to privately held instance of RecvReq so make a copy if you want to
// retain it.
func (rr *RingReader) RecvReq() *RecvReq {
	return rr.req()
}

// Data gets retrieved packet's data. Please note that the underlying
// array of returned slice is owned by SNF API. Please make a copy if
// you want to retain it. The consecutive Next() call may erase this
// slice without prior notice.
func (rr *RingReader) Data() []byte {
	return rr.req().Data()
}

// Avail shows how many packets are cached, i.e. left to read without
// calling SNF API to retrieve new packets.  Mostly used for testing
// purposes.
func (rr *RingReader) Avail() int {
	return rr.received - rr.index
}

// Err returns error which was encountered during the last RingReader
// operation on a ring. If Next() method returned false, the error
// may be revised here.
func (rr *RingReader) Err() error {
	return rr.err
}

// RingQInfo provides access the most recent Ring queue info.
func (rr *RingReader) RingQInfo() (q *RingQInfo) {
	return &rr.qinfo
}

// Free returns all packets that were retrieved but not exposed to the
// user. Usually you should do this upon and only upon finishing
// working on the receiver.
//
// Note that now, running this function is redundant if you don't
// intend to use underlying ring further until it Close()-s.
// Nevertheless, the use of this function is encouraged anyway as a
// matter of good code style.
func (rr *RingReader) Free() error {
	if len(rr.reqs) == 1 {
		return nil
	}
	return rr.ReturnMany(rr.reqs[:rr.received], &rr.qinfo)
}

// LoopNext is similar to Next() method but this one loops if EAGAIN
// is encountered. It means that timeout hit and the port should be
// polled again.
func (rr *RingReader) LoopNext() bool {
	for !rr.Next() {
		if rr.Err() != syscall.EAGAIN {
			return false
		}
	}
	return true
}
