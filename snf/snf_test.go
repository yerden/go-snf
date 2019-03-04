// Copyright 2019 Yerden Zhumabekov. All rights reserved.
//
// Use of this source code is governed by MIT license which
// can be found in the LICENSE file in the root of the source
// tree.

package snf

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	//"github.com/davecgh/go-spew/spew"
	"github.com/google/gopacket"
)

func newAssert(t *testing.T, fail bool) func(bool) {
	return func(expected bool) {
		if !expected {
			t.Helper()
			t.Error("Something's not right")
			if fail {
				t.FailNow()
			}
		}
	}
}

// mock handler
func handle(ci gopacket.CaptureInfo, data []byte) {
}

func setup(t *testing.T) (func(*testing.T), error) {
	assert := newAssert(t, false)

	var err error
	// set app id
	err = os.Setenv("SNF_APP_ID", "32")
	assert(err == nil)

	// set number of rings to 2
	err = os.Setenv("SNF_NUM_RINGS", "2")
	assert(err == nil)

	return func(t *testing.T) {}, Init()
}

func TestInit(t *testing.T) {
	assertFail := newAssert(t, true)

	teardown, err := setup(t)
	defer teardown(t)

	assertFail(err == nil)
}

func TestInject(t *testing.T) {
	assertFail := newAssert(t, true)
	assert := newAssert(t, false)

	teardown, err := setup(t)
	defer teardown(t)
	assertFail(err == nil)

	h, err := OpenInjectHandle(0, 0)
	assertFail(err == nil)
	defer h.Close()

	signal.Notify(h.SigChannel(), syscall.SIGUSR1)

	eth := []byte{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // dst mac
		0x0, 0x11, 0x22, 0x33, 0x44, 0x55, // src mac
		0x08, 0x0, // ether type
	}

	ip := []byte{
		0x45, 0x0, 0x0, 0x3c, 0xa6, 0xc3,
		0x40, 0x0, 0x40, 0x06, 0x3d, 0xd8, // ip header
		0xc0, 0xa8, 0x50, 0x2f, // src ip
		0xc0, 0xa8, 0x50, 0x2c, // dst ip
	}

	tcp := []byte{
		0xaf, 0x14, // src port
		0x0, 0x50, // dst port
	}

	packet := append(append(eth, ip...), tcp...)

	s := h.NewSender(time.Second, 0)
	assert(s.Send(packet) == nil)
	assert(s.SendVec(eth, ip, tcp) == nil)
	err = s.Sched(1000, packet)
	assert(IsEnotsup(err) || err == nil)
	err = s.SchedVec(1000, eth, ip, tcp)
	assert(IsEnotsup(err) || err == nil)

	// kiling spree and wait a bit
	syscall.Kill(syscall.Getpid(), syscall.SIGUSR1)
	time.Sleep(100 * time.Millisecond)

	assert(s.Send(packet) == io.EOF)
	assert(s.SendVec(eth, ip, tcp) == io.EOF)
	assert(s.Sched(1000, packet) == io.EOF)
	assert(s.SchedVec(1000, eth, ip, tcp) == io.EOF)
}

func TestHandleRing(t *testing.T) {
	assertFail := newAssert(t, true)
	assert := newAssert(t, false)

	teardown, err := setup(t)
	defer teardown(t)

	assertFail(err == nil)

	ifa, err := GetIfAddrs()
	assert(err == nil)
	assert(len(ifa) > 0)

	portnum := ifa[0].PortNum
	h, err := OpenHandleDefaults(portnum)
	assert(err == nil)
	assert(h != nil)

	r0, err := h.OpenRing()
	assert(err == nil)
	assert(r0 != nil)

	r1, err := h.OpenRing()
	assert(err == nil)
	assert(r1 != nil)

	_, err = h.OpenRing()
	assert(IsEbusy(err))

	// we've got 2 opened rings
	assert(len(h.Rings()) == 2)

	// attempt to close: fail, 2 to go
	assert(IsEbusy(h.Close()))

	// close 0
	assert(r0.Close() == nil)

	// attempt to close: fail, 1 to go
	assert(IsEbusy(h.Close()))

	// close 1
	assert(r1.Close() == nil)

	// attempt to close: ok
	assert(h.Close() == nil)
}

func TestApp(t *testing.T) {
	assertFail := newAssert(t, true)
	assert := newAssert(t, false)

	teardown, err := setup(t)
	defer teardown(t)

	assertFail(err == nil)
	ifa, err := GetIfAddrs()
	assert(err == nil)

	assert(len(ifa) > 0)

	var wg sync.WaitGroup
	counters := make([]uint64, len(ifa))
	// handle all ports
	for i := range ifa {
		h, err := OpenHandleDefaults(ifa[i].PortNum)
		assert(err == nil)
		assert(h != nil)
		defer h.Wait()
		defer h.Close()
		signal.Notify(h.SigChannel(), syscall.SIGUSR1)

		// opening SNF_NUM_RINGS rings
		var rings []*Ring
		for x := 0; x < 2; x++ {
			r, err := h.OpenRing()
			assert(err == nil)
			assert(r != nil)
			rings = append(rings, r)
		}
		_, err = h.OpenRing()
		assert(IsEbusy(err))

		assert(h.Start() == nil)
		// processing traffic from all rings
		for _, r := range rings {
			wg.Add(1)
			go func(r *Ring, counter *uint64) {
				defer wg.Done()
				defer r.Close()
				rcv := r.NewReceiver(time.Second, 256)
				defer rcv.Free()
				snaplen := 1234
				err := rcv.SetBPF(snaplen, "vlan and tcp")
				if err != nil {
					return
				}

				for rcv.Next() {
					atomic.AddUint64(counter, 1)
					assert(snaplen == rcv.BPFResult())
				}

				// we should be closed by signal
				assert(rcv.Err() == io.EOF)
			}(r, &counters[i])
		}
	}

	done := make(chan bool, 1)
	go func() {
		// waiting for ring goroutines to exit
		defer close(done)
		wg.Wait()
		done <- true
	}()

	// killing spree
	time.Sleep(100 * time.Millisecond)
	syscall.Kill(syscall.Getpid(), syscall.SIGUSR1)

	// check to see if all ring goroutines exit
	assert(<-done)
	fmt.Println(counters)
}

func ExampleOpenHandle_first() {
	// This shows how to initialize a handle

	// First, initialize SNF library.
	if err := Init(); err != nil {
		return
	}

	// Initialize handle for port 0
	h, err := OpenHandle(
		0,                           // number of port
		3,                           // number of rings
		RssIP|RssSrcPort|RssDstPort, // rss flags
		PShared|RxDuplicate,         // flags
		256,                         // Megabytes for dataring size
	)

	if err != nil {
		return
	}

	defer h.Close()

	// initialize handle for port 1,
	// with default arguments which mostly imply
	// that we use environment variables to
	// alter the handle behaviour
	h, err = OpenHandleDefaults(1)
	if err != nil {
		return
	}
	defer h.Close()
}

func ExampleOpenHandle_second() {
	// this function will exit only on signals
	// SIGINT or SIGSEGV or when both goroutines
	// handling rings will exit
	if err := Init(); err != nil {
		return
	}

	// sample default handler
	h, err := OpenHandleDefaults(0)
	if err != nil {
		return
	}
	// Wait() is needed because we should wait
	// for successful closing of rings and the handle;
	// this is especially important in main().
	defer h.Wait()
	// close handle, it's safe to close handle
	// even if it was closed before
	defer h.Close()

	// handling signals in case of abnormal exit once a
	// signal is raised all the rings and handle will be
	// closed. After that, in case the traffic handling goroutines
	// call Recv() on a ring, it will return io.EOF. This
	// would signal those goroutines to exit as well.
	signal.Notify(h.SigChannel(),
		syscall.SIGINT,
		syscall.SIGSEGV,
	)

	// start capturing traffic
	if err := h.Start(); err != nil {
		return
	}
	var wg sync.WaitGroup
	// wait for goroutines to exit
	defer wg.Wait()
	wg.Add(2)
	go func() {
		defer wg.Done()
		r, err := h.OpenRing()
		if err != nil {
			return
		}
		defer r.Close()
		// handle this ring and read packets
		// until io.EOF
	}()

	go func() {
		defer wg.Done()
		r, err := h.OpenRing()
		if err != nil {
			return
		}
		defer r.Close()
		// handle this ring and read packets
		// until io.EOF
	}()
}

func ExampleRingReceiver() {
	var h *Handle
	h, err := OpenHandleDefaults(0)
	if err != nil {
		return
	}
	defer h.Close()

	// open ring
	r, err := h.OpenRing()
	if err != nil {
		return
	}
	defer r.Close()

	// abstract ring operations in a RingReceiver object
	recv := r.NewReceiver(
		time.Second, // timeout for receiving new packet
		256,         // how many packets to receive in one call
	)
	// if we exit, return all unclaimed packets to ring.
	defer recv.Free()

	// start capturing traffic
	if err := h.Start(); err != nil {
		return
	}

	// process traffic in bufio.Scanner-like way
	for recv.LoopNext() {
		handle(recv.RecvReq().CaptureInfo(), recv.Data())
	}

	// Alternatively, you may utilize gopacket.ZeroCopyPacketDataSource
	// or gopacket.PacketDataSource.
	//
	// if err is io.EOF that means the ring was closed and receiving
	// operations should halt.
	for {
		data, ci, err := recv.ZeroCopyReadPacketData()
		if err == io.EOF {
			return
		} else if err != nil {
			panic(err.Error())
		}
		handle(ci, data)
	}
}
