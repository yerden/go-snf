package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/yerden/go-snf/snf"
)

var devName = flag.String("i", "", "Specify interface name")
var portID = flag.Int("n", 0, "Specify port id")
var nPkts = flag.Int("c", 0, "Number of packets to capture")
var pcapFile = flag.String("w", "", "Pcap file name to write")

// This is an example application.
// Please set SNF_APP_ID, SNF_NUM_RINGS, SNF_DATARING_SIZE
// and run as root.
func main() {
	// init SNF
	if err := snf.Init(); err != nil {
		panic(err.Error())
	}

	var w *pcapgo.NgWriter
	wmtx := &sync.Mutex{}
	if *pcapFile != "" {
		f, err := os.Open(*pcapFile)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		w, err = pcapgo.NewNgWriter(f, layers.LinkTypeEthernet)
		if err != nil {
			log.Fatal(err)
		}
		defer w.Flush()
	}

	var portNum uint32

	if *devName != "" {
		ifa, err := snf.GetIfAddrByName(*devName)
		if err != nil {
			log.Fatalln("not found interface:", *devName)
		}
		portNum = ifa.PortNum()
	} else {
		portNum = uint32(*portID)
	}

	// set SNF_NUM_RINGS, SNF_DATARING_SIZE in environment
	dev, err := snf.OpenHandle(portNum,
		snf.HandlerOptRssFlags(snf.RssIP|snf.RssSrcPort|snf.RssDstPort),
		snf.HandlerOptFlags(snf.PShared),
	)
	if err != nil {
		log.Fatal(err.Error())
	}

	// open rings until exhausted
	var rings []*snf.Ring
	for {
		ring, err := dev.OpenRing()
		if err == nil {
			log.Println("opened ring #", len(rings), "on port #", portNum)
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

			j := 0
			for rcv.LoopNext() {
				req := rcv.RecvReq()
				// TODO: filter
				wmtx.Lock()
				err := w.WritePacket(req.CaptureInfo(), req.Data())
				wmtx.Unlock()
				if err != nil {
					log.Fatal(err)
				}
				if j++; *nPkts != 0 && j == *nPkts {
					break
				}
			}

			if rcv.Err() != nil {
				log.Fatal(rcv.Err())
			}
			log.Printf("received %d bytes\n", j)
		}(i, ring)
	}
	wg.Wait()
}
