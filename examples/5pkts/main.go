package main

import (
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

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
		for i, _ := range ifa {
			log.Println(ifa[i])
		}
	}

	// choose first port
	portnum := ifa[0].PortNum

	// set SNF_NUM_RINGS, SNF_DATARING_SIZE in environment
	dev, err := snf.OpenHandle(portnum(),
		snf.HandlerOptRssFlags(snf.RssIP|snf.RssSrcPort|snf.RssDstPort),
		snf.HandlerOptFlags(snf.PShared),
	)
	if err != nil {
		panic(err.Error())
	}

	// open rings until exhausted
	var rings []*snf.Ring
	for {
		ring, err := dev.OpenRing()
		if err == nil {
			log.Println("opened ring #", len(rings), "on port #", portnum)
			rings = append(rings, ring)
			defer ring.Close()
		} else if err == syscall.Errno(syscall.EBUSY) {
			log.Println("unable to open more rings")
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
			rcv := snf.NewReader(ring,
				time.Millisecond, // 1 ms to wait for packets
				200,              // size of packet bunch
			)
			defer rcv.Free()
			ch := make(chan os.Signal)
			signal.Notify(ch, syscall.SIGINT, syscall.SIGUSR1)
			rcv.NotifyWith(ch)
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
