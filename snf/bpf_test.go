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

func BenchmarkBulkPcapBPFGood(b *testing.B) {
	res, err := pcapFilterTest(packet[:], snaplen, goodBPF, b.N)
	if err != nil {
		b.Fatal("unable to make a filter")
	}
	if res != snaplen {
		fmt.Println("res=", res)
		b.Fatal("filter supposed to be good")
	}
}

func BenchmarkBulkPcapBPFBad(b *testing.B) {
	res, err := pcapFilterTest(packet[:], snaplen, badBPF, b.N)
	if err != nil {
		b.Fatal("unable to make a filter")
	}
	if res == snaplen {
		fmt.Println("res=", res)
		b.Fatal("filter supposed to be bad")
	}
}
