// Copyright 2019 Yerden Zhumabekov. All rights reserved.
//
// Use of this source code is governed by MIT license which
// can be found in the LICENSE file in the root of the source
// tree.

package snf

/*
#include <stdlib.h>
#include "wrapper.h"
*/
import "C"

import (
	"fmt"
	"os"
	"reflect"
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
	*Ring

	timeout time.Duration
	reqVec  []RecvReq

	// killed
	stopped uint32

	sig os.Signal

	err error

	// index of current snf_recv_req
	n int
}

func extendReqVec(vec []RecvReq) []RecvReq {
	sh := (*reflect.SliceHeader)(unsafe.Pointer(&vec))
	sh.Cap = sh.Len
	return vec
}

func newReqVec(n int) (vec []RecvReq) {
	sh := (*reflect.SliceHeader)(unsafe.Pointer(&vec))
	sh.Data = uintptr(C.malloc(C.size_t(n) * C.sizeof_struct_snf_recv_req))
	sh.Len = n
	sh.Cap = n
	return vec
}

func freeReqVec(vec []RecvReq) {
	sh := (*reflect.SliceHeader)(unsafe.Pointer(&vec))
	C.free(unsafe.Pointer(sh.Data))
}

// ErrSignal wraps os.Signal as an error.
type ErrSignal struct{ os.Signal }

// Error implements error interface.
func (e *ErrSignal) Error() string {
	return fmt.Sprintf("Caught signal: %v", e.Signal)
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
	rr := &RingReader{
		Ring:    r,
		timeout: timeout,
		reqVec:  newReqVec(burst),
	}

	runtime.SetFinalizer(rr, func(rr *RingReader) {
		freeReqVec(rr.reqVec)
	})
	return rr
}

// Next gets next packet out of ring. If true, the operation is a
// success, otherwise you should halt all actions on the receiver
// until Err() error is examined and needed actions are performed.
func (rr *RingReader) Next() bool {
	if rr.n++; rr.n >= len(rr.reqVec) {
		if atomic.LoadUint32(&rr.stopped) > 0 {
			rr.err = &ErrSignal{rr.sig}
			return false
		}

		if rr.err = rr.ReturnMany(rr.reqVec, nil); rr.err != nil {
			rr.reqVec = rr.reqVec[:0]
			return false
		}

		rr.reqVec = extendReqVec(rr.reqVec)
		n, err := rr.RecvMany(rr.timeout, rr.reqVec, nil)
		if rr.err = err; rr.err != nil {
			rr.reqVec = rr.reqVec[:0]
			return false
		}

		rr.reqVec = rr.reqVec[:n]
		rr.n = 0
	}

	return true
}

func (rr *RingReader) req() *RecvReq {
	return &rr.reqVec[rr.n]
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
	return rr.ReturnMany(rr.reqVec, nil)
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
