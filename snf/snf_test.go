// Copyright 2019 Yerden Zhumabekov. All rights reserved.
//
// Use of this source code is governed by MIT license which
// can be found in the LICENSE file in the root of the source
// tree.
package snf

import (
	"io"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"testing"
	"time"

	//"github.com/davecgh/go-spew/spew"
	"github.com/google/gopacket"
)

func assert(t *testing.T, expected bool) {
	if t.Helper(); !expected {
		t.Error("Something's not right")
	}
}

func assertFail(t *testing.T, expected bool) {
	if t.Helper(); !expected {
		t.Error("Something's not right")
		t.FailNow()
	}
}

// mock handler
func handle(ci gopacket.CaptureInfo, data []byte) {
}

func TestInit(t *testing.T) {
	var err error
	// set app id
	err = os.Setenv("SNF_APP_ID", "32")
	assert(t, err == nil)

	// set number of rings to 2
	err = os.Setenv("SNF_NUM_RINGS", "2")
	assert(t, err == nil)

	err = Init()
	assertFail(t, err == nil)

	ifa, err := GetIfAddrs()
	assert(t, err == nil)
	assert(t, len(ifa) > 0)

	// handle all ports
	for i, _ := range ifa {
		h, err := OpenHandleDefaults(ifa[i].PortNum)
		assert(t, err == nil)
		assert(t, h != nil)
		defer h.Wait()
		defer h.Close()
		signal.Notify(h.SigChannel(),
			syscall.SIGTERM,
			syscall.SIGINT,
			syscall.SIGSEGV,
		)

		// opening SNF_NUM_RINGS rings
		r, err := h.OpenRing()
		assert(t, err == nil)
		assert(t, r != nil)
		defer r.Close()

		r, err = h.OpenRing()
		assert(t, err == nil)
		assert(t, r != nil)
		defer r.Close()

		r, err = h.OpenRing()
		assert(t, IsEbusy(err))
	}
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
	// for successfull closing of rings and the handle;
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

func ExampleNewNetBPF() {
	var recv *RingReceiver
	// create recv with ring's NewReceiver() method
	// ...

	// compile golang.org/x/net/bpf virtual machine.
	//
	// compilation is done with libpcap library, filter
	// is executed natively.
	bpf, err := NewNetBPF(
		65535,                          // max snap len
		"vlan and tcp and dst port 53", // bpf expression
	)
	if err != nil {
		return
	}

	// set the filter;
	// remember, setting new filter replaces previous one
	recv.SetRawFilter(bpf)
}

func ExampleNewPcapBPF() {
	var recv *RingReceiver
	// create recv with ring's NewReceiver() method
	// ...

	// compile libpcap BPF virtual machine.
	//
	// compilation and execution is done within libpcap
	// library
	bpf, err := NewPcapBPF(
		65535,                          // max snap len
		"vlan and tcp and dst port 53", // bpf expression
	)
	if err != nil {
		return
	}

	// set the filter;
	// remember, setting new filter replaces previous one
	recv.SetFilter(bpf)
}

func ExampleRingReceiver_SetFilter() {
	var recv *RingReceiver
	// create recv with ring's NewReceiver() method
	// ...

	// see NewNetBPF() or NewPcapBPF() for respective
	// examples on BPF filtering.
	//
	// Alternatively to BPF, custom filter may be devised.
	//
	// For example, we don't want to see packets
	// with length over 1000 bytes on working days.
	filter := func(ci gopacket.CaptureInfo, data []byte) bool {
		if wd := ci.Timestamp.Weekday(); wd == time.Saturday || wd == time.Sunday {
			return true
		}
		return ci.Length < 1000
	}

	// set the filter;
	// remember, setting new filter replaces previous one
	recv.SetFilter(FilterFunc(filter))
}
