package main

import (
	"log"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/yerden/go-snf/snf"
)

// This is an example application.
// Please set SNF_APP_ID, SNF_NUM_RINGS, SNF_DATARING_SIZE
// and run as root.
func main() {
	// init SNF
	if err := snf.Init(); err != nil {
		panic(err.Error())
	}

	// show all ports information
	ifa, err := snf.GetIfAddrs()
	if err != nil {
		panic(err.Error())
	} else {
		spew.Dump(ifa)
	}

	// choose first port
	portnum := ifa[0].PortNum

	dev, err := snf.OpenHandle(portnum,
		0, // set SNF_NUM_RINGS
		snf.RssIP|snf.RssSrcPort|snf.RssDstPort,
		snf.PShared,
		0, // set SNF_DATARING_SIZE
	)
	if err != nil {
		panic(err.Error())
	}
	signal.Notify(dev.SigChannel(), syscall.SIGINT, syscall.SIGUSR1)

	// open rings until exhausted
	var rings []*snf.Ring
	for {
		ring, err := dev.OpenRing()
		if err == nil {
			spew.Println("opened ring #", len(rings), "on port #", portnum)
			rings = append(rings, ring)
			defer ring.Close()
		} else if err == syscall.Errno(syscall.EBUSY) {
			spew.Println("unable to open more rings")
			break
		} else {
			panic(err.Error())
		}
	}

	var wg sync.WaitGroup
	for i, ring := range rings {
		wg.Add(1)
		go func(i int, ring *snf.Ring) {
			defer wg.Done()
			n := 5
			defer log.Printf("ring #%d received %d packets\n", i, n)
			rcv := ring.NewReceiver(
				time.Millisecond, // 1 ms to wait for packets
				200,              // size of packet bunch
			)
			defer rcv.Free()
			for j := 0; j < n; j++ {
				if !rcv.LoopNext() {
					panic(rcv.Err().Error())
				}
				log.Printf("received %d bytes\n", len(rcv.Data()))
			}
		}(i, ring)
	}
	wg.Wait()
}
