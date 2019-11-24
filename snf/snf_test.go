// Copyright 2019 Yerden Zhumabekov. All rights reserved.
//
// Use of this source code is governed by MIT license which
// can be found in the LICENSE file in the root of the source
// tree.

package snf_test

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/yerden/go-snf/snf"
)

func newAssert(t testing.TB, fail bool) func(bool, ...interface{}) {
	return func(expected bool, v ...interface{}) {
		if !expected {
			t.Helper()
			if t.Error(v...); fail {
				t.FailNow()
			}
		}
	}
}

// mock handler
func handleReq(*snf.RecvReq) {
}

func handlePacket(ci gopacket.CaptureInfo, data []byte) {
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

	return func(t *testing.T) {}, snf.Init()
}

func TestInit(t *testing.T) {
	assertFail := newAssert(t, true)

	teardown, err := setup(t)
	defer teardown(t)

	assertFail(err == nil)
}

func TestGetIfAddrs(t *testing.T) {
	assertFail := newAssert(t, true)
	assert := newAssert(t, false)

	teardown, err := setup(t)
	defer teardown(t)
	assertFail(err == nil)

	ifa, err := snf.GetIfAddrs()
	assertFail(err == nil)
	assertFail(len(ifa) > 0)

	for _, iface := range ifa {
		iface_got, err := snf.GetIfAddrByName(iface.Name())
		assertFail(err == nil)
		assert(iface.Name() == iface_got.Name())

		iface_got, err = snf.GetIfAddrByHW(iface.MACAddr())
		assertFail(err == nil)
		assert(bytes.Equal(iface.MACAddr(), iface_got.MACAddr()))
	}
	iface, err := snf.GetIfAddrByName("some_eth0")
	assert(err == nil && iface == nil)
	iface, err = snf.GetIfAddrByHW([]byte{0, 1, 2, 3, 4, 5})
	assert(err == nil && iface == nil)
}

func TestHandleRing(t *testing.T) {
	assertFail := newAssert(t, true)
	assert := newAssert(t, false)

	teardown, err := setup(t)
	defer teardown(t)

	assertFail(err == nil)

	ifa, err := snf.GetIfAddrs()
	assert(err == nil)
	assert(len(ifa) > 0)

	portnum := ifa[0].PortNum()
	h, err := snf.OpenHandle(portnum)
	assert(err == nil)
	assert(h != nil)

	r0, err := h.OpenRing()
	assert(err == nil)
	assert(r0 != nil)

	r1, err := h.OpenRing()
	assert(err == nil)
	assert(r1 != nil)

	_, err = h.OpenRing()
	assert(err == syscall.EBUSY)

	// attempt to close: fail, 2 to go
	assert(err == syscall.EBUSY)

	// close 0
	assert(r0.Close() == nil)

	// attempt to close: fail, 1 to go
	assert(h.Close() == syscall.EBUSY)

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
	ifa, err := snf.GetIfAddrs()
	assert(err == nil)

	assert(len(ifa) > 0)

	var wg sync.WaitGroup
	counters := make([]uint64, len(ifa))
	// handle all ports
	for i := range ifa {
		h, err := snf.OpenHandle(ifa[i].PortNum())
		assert(err == nil)
		assert(h != nil)
		defer h.Close()

		// opening SNF_NUM_RINGS rings
		var rings []*snf.Ring
		for x := 0; x < 2; x++ {
			r, err := h.OpenRing()
			assert(err == nil)
			assert(r != nil)
			defer r.Close()
			rings = append(rings, r)
		}
		_, err = h.OpenRing()
		assert(err == syscall.EBUSY)

		assert(h.Start() == nil)
		// processing traffic from all rings
		for _, r := range rings {
			wg.Add(1)
			go func(r *snf.Ring, counter *uint64) {
				defer wg.Done()
				rcv := snf.NewReader(r, time.Second, 256)
				defer rcv.Free()

				ch := make(chan os.Signal, 1)
				signal.Notify(ch, syscall.SIGUSR1)
				rcv.NotifyWith(ch)

				for rcv.Next() {
					atomic.AddUint64(counter, 1)
				}

				// we should be closed by signal
				err := rcv.Err()
				assert(err != nil)
				assert(err.(*snf.ErrSignal).Signal == syscall.SIGUSR1)
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

func ExampleOpenHandle_one() {
	// This shows how to initialize a handle

	// First, initialize SNF library.
	if err := snf.Init(); err != nil {
		return
	}

	flags := snf.RssIP | snf.RssSrcPort | snf.RssDstPort
	// Initialize handle for port 0
	h, err := snf.OpenHandle(
		0,                             // number of port
		snf.HandlerOptNumRings(3),     // number of rings
		snf.HandlerOptRssFlags(flags), // rss flags
		snf.HandlerOptFlags(snf.PShared),
		snf.HandlerOptFlags(snf.RxDuplicate), // flags
		snf.HandlerOptDataRingSize(256),      // Megabytes for dataring size
	)

	if err != nil {
		return
	}

	defer h.Close()

	// initialize handle for port 1,
	// with default arguments which mostly imply
	// that we use environment variables to
	// alter the handle behaviour
	h, err = snf.OpenHandle(1)
	if err != nil {
		return
	}
	defer h.Close()
}

func ExampleOpenHandle_two() {
	if err := snf.Init(); err != nil {
		return
	}

	// sample default handler
	h, err := snf.OpenHandle(0)
	if err != nil {
		return
	}
	defer h.Close()

	// start capturing traffic
	if err := h.Start(); err != nil {
		return
	}
	defer h.Stop()

	var wg sync.WaitGroup
	// wait for goroutines to exit
	defer wg.Wait()

	// open 2 rings and work on them; you should ensure there's at
	// least 2 rings through environment variables
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := h.OpenRing()
			if err != nil {
				return
			}
			defer r.Close()
			// handle this ring and read packets
			// ...
		}()
	}
}

func ExampleRingReader() {
	var h *snf.Handle
	h, err := snf.OpenHandle(0)
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

	// abstract ring operations in a RingReader object
	recv := snf.NewReader(
		r,           // Underlying ring
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
		handleReq(recv.RecvReq())
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
		handlePacket(ci, data)
	}
}
