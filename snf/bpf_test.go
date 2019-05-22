// Copyright 2019 Yerden Zhumabekov. All rights reserved.
//
// Use of this source code is governed by MIT license which
// can be found in the LICENSE file in the root of the source
// tree.
package snf

import (
	"fmt"
	"testing"
)

var (
	snaplen = 65535
	packet  = [...]byte{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // dst mac
		0x0, 0x11, 0x22, 0x33, 0x44, 0x55, // src mac
		0x08, 0x0, // ether type
		0x45, 0x0, 0x0, 0x3c, 0xa6, 0xc3, 0x40, 0x0, 0x40, 0x06, 0x3d, 0xd8, // ip header
		0xc0, 0xa8, 0x50, 0x2f, // src ip
		0xc0, 0xa8, 0x50, 0x2c, // dst ip
		0xaf, 0x14, // src port
		0x0, 0x50, // dst port
	}
	goodBPF = "ip and tcp and port 80"
	badBPF  = "udp and port 80"
)

// badBPF  = "udp and port 80"
func nativeBadFilter(p []byte, snaplen int) int {
	if len(p) < 14 {
		return 0
	}

	etherhdr, ip := p[:14], p[14:]
	if etherhdr[12] != 0x8 || etherhdr[13] != 0x00 {
		return 0
	}

	iplen := int((ip[0] & 0xf) * 4)
	if iplen < 20 || len(ip) < iplen || ip[9] != 17 {
		return 0
	}

	udp := ip[iplen:]
	if len(udp) < 4 {
		return 0
	}

	if udp[0] == 0 && udp[1] == 80 {
		return snaplen
	}

	if udp[2] == 0 && udp[3] == 80 {
		return snaplen
	}
	return 0
}

// goodBPF = "ip and tcp and port 80"
func nativeGoodFilter(p []byte, snaplen int) int {
	if len(p) < 14 {
		return 0
	}

	etherhdr, ip := p[:14], p[14:]
	if etherhdr[12] != 0x8 || etherhdr[13] != 0x00 {
		return 0
	}

	iplen := int((ip[0] & 0xf) * 4)
	if iplen < 20 || len(ip) < iplen || ip[9] != 6 {
		return 0
	}

	tcp := ip[iplen:]
	if len(tcp) < 4 {
		return 0
	}

	if tcp[0] == 0 && tcp[1] == 80 {
		return snaplen
	}

	if tcp[2] == 0 && tcp[3] == 80 {
		return snaplen
	}
	return 0
}

func BenchmarkBulkPcapBPFGood(b *testing.B) {
	res, err := pcapFilterTest(packet[:], snaplen, goodBPF, b.N, true)
	if err != nil {
		b.Fatal("unable to make a filter")
	}
	if res != snaplen {
		fmt.Println("res=", res)
		b.Fatal("filter supposed to be good")
	}
}

func BenchmarkNativeFilterGood(b *testing.B) {
	for i := 0; i < b.N; i++ {
		res := nativeGoodFilter(packet[:], snaplen)
		if res != snaplen {
			fmt.Println("res=", res)
			b.Fatal("filter supposed to be good")
		}
	}
}

func BenchmarkNativeFilterBad(b *testing.B) {
	for i := 0; i < b.N; i++ {
		res := nativeBadFilter(packet[:], snaplen)
		if res == snaplen {
			fmt.Println("res=", res)
			b.Fatal("filter supposed to be bad")
		}
	}
}

func BenchmarkBulkPcapBPFBad(b *testing.B) {
	res, err := pcapFilterTest(packet[:], snaplen, badBPF, b.N, true)
	if err != nil {
		b.Fatal("unable to make a filter")
	}
	if res == snaplen {
		fmt.Println("res=", res)
		b.Fatal("filter supposed to be bad")
	}
}

func BenchmarkSinglePcapBPFGood(b *testing.B) {
	res, err := pcapFilterTest(packet[:], snaplen, goodBPF, b.N, false)
	if err != nil {
		b.Fatal("unable to make a filter")
	}
	if res != snaplen {
		fmt.Println("res=", res)
		b.Fatal("filter supposed to be good")
	}
}

func BenchmarkSinglePcapBPFBad(b *testing.B) {
	res, err := pcapFilterTest(packet[:], snaplen, badBPF, b.N, false)
	if err != nil {
		b.Fatal("unable to make a filter")
	}
	if res == snaplen {
		fmt.Println("res=", res)
		b.Fatal("filter supposed to be bad")
	}
}
