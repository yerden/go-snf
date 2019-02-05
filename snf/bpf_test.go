// Copyright 2019 Yerden Zhumabekov. All rights reserved.
//
// Use of this source code is governed by MIT license which
// can be found in the LICENSE file in the root of the source
// tree.
package snf_test

import (
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/yerden/go-snf/snf"
)

var (
	snaplen int = 65535
	packet      = [...]byte{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // dst mac
		0x0, 0x11, 0x22, 0x33, 0x44, 0x55, // src mac
		0x08, 0x0, // ether type
		0x45, 0x0, 0x0, 0x3c, 0xa6, 0xc3, 0x40, 0x0, 0x40, 0x06, 0x3d, 0xd8, // ip header
		0xc0, 0xa8, 0x50, 0x2f, // src ip
		0xc0, 0xa8, 0x50, 0x2c, // dst ip
		0xaf, 0x14, // src port
		0x0, 0x50, // dst port
	}
	goodBPF string = "ip and tcp and port 80"
	badBPF  string = "udp and port 80"
)

func newNetBPF(t *testing.T, bpffilter string) snf.RawFilter {
	filter, err := snf.NewNetBPF(snaplen, bpffilter)
	if err != nil {
		t.Fatalf("failed create NetBPF: %v", err)
	}
	return filter
}

func newPcapBPF(t *testing.T, bpffilter string) snf.Filter {
	filter, err := snf.NewPcapBPF(snaplen, bpffilter)
	if err != nil {
		t.Fatalf("failed create PcapBPF: %v", err)
	}
	return filter
}

func TestNetBPF(t *testing.T) {
	filter := newNetBPF(t, goodBPF)

	if !filter.Matches(packet[:]) {
		t.Fatal("filter must match the packet")
	}

	filter = newNetBPF(t, badBPF)
	if filter.Matches(packet[:]) {
		t.Fatal("filter must not match the packet")
	}
}

func TestPcapBPF(t *testing.T) {

	filter := newPcapBPF(t, goodBPF)
	ci := gopacket.CaptureInfo{
		InterfaceIndex: 0,
		CaptureLength:  len(packet),
		Length:         len(packet),
		Timestamp:      time.Now(),
	}

	if !filter.Matches(ci, packet[:]) {
		t.Fatal("filter must match the packet")
	}

	filter = newPcapBPF(t, badBPF)
	if filter.Matches(ci, packet[:]) {
		t.Fatal("filter must not match the packet")
	}
}

func BenchmarkNetBPFGood(b *testing.B) {
	filter, _ := snf.NewNetBPF(snaplen, goodBPF)

	for i := 0; i < b.N; i++ {
		if !filter.Matches(packet[:]) {
			b.Fatal("filter must match the packet")
		}
	}
}

func BenchmarkPcapBPFGood(b *testing.B) {
	filter, _ := snf.NewPcapBPF(snaplen, goodBPF)
	ci := gopacket.CaptureInfo{
		InterfaceIndex: 0,
		CaptureLength:  len(packet),
		Length:         len(packet),
		Timestamp:      time.Now(),
	}

	for i := 0; i < b.N; i++ {
		if !filter.Matches(ci, packet[:]) {
			b.Fatal("filter must match the packet")
		}
	}
}

func BenchmarkNetBPFBad(b *testing.B) {
	filter, _ := snf.NewNetBPF(snaplen, badBPF)

	for i := 0; i < b.N; i++ {
		if filter.Matches(packet[:]) {
			b.Fatal("filter must not match the packet")
		}
	}
}

func BenchmarkPcapBPFBad(b *testing.B) {
	filter, _ := snf.NewPcapBPF(snaplen, badBPF)
	ci := gopacket.CaptureInfo{
		InterfaceIndex: 0,
		CaptureLength:  len(packet),
		Length:         len(packet),
		Timestamp:      time.Now(),
	}

	for i := 0; i < b.N; i++ {
		if filter.Matches(ci, packet[:]) {
			b.Fatal("filter must not match the packet")
		}
	}
}
