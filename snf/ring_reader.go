// Copyright 2019 Yerden Zhumabekov. All rights reserved.
//
// Use of this source code is governed by MIT license which
// can be found in the LICENSE file in the root of the source
// tree.

package snf

/*
#include "wrapper.h"
#include "ring_reader.h"
*/
import "C"

import (
	"fmt"
	"os"
	"runtime"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

// RingReader wraps SNF's borrow-many-return-many model of packets
// retrieval, along with google's gopacket interface. This allows us
// to access low-level SNF API but maintain compatibility with
// gopacket's layers decoding abilities.
type RingReader struct {
	reader *C.struct_ring_reader

	// killed
	stopped uint32

	sig os.Signal

	err error

	// index of current snf_recv_req
	n C.int
}

// ErrSignal wraps os.Signal as an error.
type ErrSignal struct{ os.Signal }

// Error implements error interface.
func (e *ErrSignal) Error() string {
	return fmt.Sprintf("Caught signal: %v", e.Signal)
}

func (rr *RingReader) recvReq(n C.int) *RecvReq {
	p := unsafe.Pointer(rr.reader)
	p = unsafe.Pointer(uintptr(p) + uintptr(C.RING_READER_REQ_VECTOR_OFF))
	p = unsafe.Pointer(uintptr(p) + uintptr(n)*C.sizeof_struct_snf_recv_req)
	return (*RecvReq)(p)
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
	reader := (*C.struct_ring_reader)(C.malloc(C.ring_reader_size(C.int(burst))))
	reader.ringh = (*C.struct_snf_ring)(r)
	reader.timeout_ms = dur2ms(timeout)
	reader.nreq_out = 0
	reader.nreq_in = C.int(burst)

	rr := &RingReader{reader: reader}
	runtime.SetFinalizer(rr, func(rr *RingReader) {
		C.free(unsafe.Pointer(rr.reader))
	})
	return &RingReader{reader: reader}
}

// Next gets next packet out of ring. If true, the operation is a
// success, otherwise you should halt all actions on the receiver
// until Err() error is examined and needed actions are performed.
func (rr *RingReader) Next() bool {
	if rr.n++; rr.n >= rr.reader.nreq_out {
		if atomic.LoadUint32(&rr.stopped) > 0 {
			rr.err = &ErrSignal{rr.sig}
			return false
		}

		rr.err = retErr(C.ring_reader_recharge(rr.reader))
		if rr.err != nil {
			rr.reader.nreq_out = 0
			return false
		}
		rr.n = 0
	}

	return true
}

func (rr *RingReader) req() *RecvReq {
	return rr.recvReq(rr.n)
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

// Err returns error which was encountered during the last RingReader
// operation on a ring. If Next() method returned false, the error
// may be revised here.
func (rr *RingReader) Err() error {
	return rr.err
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
	C.ring_reader_return_many(rr.reader)
	return nil
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

// NotifyWith installs signal notification channel which is presumably
// registered via signal.Notify.
//
// Please note that this function expects that specified channel is
// closed at some point to release acquired resources.
func (rr *RingReader) NotifyWith(ch <-chan os.Signal) {
	go func() {
		for sig := range ch {
			rr.sig = sig
			atomic.StoreUint32(&rr.stopped, 1)
			break
		}
	}()
}
