package filter

import (
	// "fmt"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var TcpPacket = []byte{
	// MAC addresses
	0xd4, 0xe6, 0xb7, 0x51, 0xa3, 0x11, 0xf8, 0x1a,
	0x67, 0x1b, 0x3e, 0xf5, 0x08, 0x00,

	// IP header, offset to proto 9
	0x45, 0x00, 0x00, 0x3c, 0x68, 0x07, 0x00, 0x00,
	0x64, 0x06, 0xfe, 0x08, 0x40, 0xe9, 0xa5, 0x66,
	0x0a, 0x2a, 0x00, 0x33,

	// TCP header
	0x00, 0x50, 0xbd, 0xfc, 0x4a, 0x22, 0x5f, 0xc4,
	0x14, 0x1f, 0xab, 0xc3, 0xa0, 0x12, 0xeb, 0x20,
	0xed, 0xec, 0x00, 0x00, 0x02, 0x04, 0x05, 0x64,
	0x04, 0x02, 0x08, 0x0a, 0x64, 0x9a, 0x66, 0xfa,
	0x00, 0x36, 0x8a, 0xa4, 0x01, 0x03, 0x03, 0x08,
}

var UdpPacket = []byte{
	// MAC addresses
	0xf8, 0x1a, 0x67, 0x1b, 0x3e, 0xf5, 0xd4, 0xe6,
	0xb7, 0x51, 0xa3, 0x11, 0x08, 0x00,

	// IP header, offset to proto 9
	0x45, 0x00, 0x00, 0x41, 0x8a, 0xbc, 0x40, 0x00,
	0x40, 0x11, 0x9b, 0x68, 0x0a, 0x2a, 0x00, 0x33,
	0x0a, 0x2a, 0x00, 0x01,

	// UDP header
	0x80, 0x0a, 0x00, 0x35, 0x00, 0x2d, 0x22, 0xee,

	// Payload
	0xf2, 0x1c, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x08, 0x63, 0x6c, 0x69,
	0x65, 0x6e, 0x74, 0x73, 0x33, 0x06, 0x67, 0x6f,
	0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d,
	0x00, 0x00, 0x1c, 0x00, 0x01,
}

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

func TestUDPFilter(t *testing.T) {
	assert := newAssert(t, false)

	f := UDPPortFilter(0x35)
	assert(f.Filter(UdpPacket) > 0)

	g := UDPPortFilter(0x20)
	assert(g.Filter(UdpPacket) == 0)
}

func TestTCPFilter(t *testing.T) {
	assert := newAssert(t, false)

	f := TCPPortFilter(0x50)
	assert(f.Filter(TcpPacket) > 0)

	g := TCPPortFilter(0x20)
	assert(g.Filter(TcpPacket) == 0)
}

func BenchmarkTCPFilter(b *testing.B) {
	f := TCPPortFilter(0x50)

	for i := 0; i < b.N; i++ {
		_ = f.Filter(TcpPacket)
	}
}

func BenchmarkUDPFilter(b *testing.B) {
	f := UDPPortFilter(0x50)

	for i := 0; i < b.N; i++ {
		_ = f.Filter(UdpPacket)
	}
}

func BenchmarkReference(b *testing.B) {
	var n int

	for i := 0; i < b.N; i++ {
		n += i
	}

	_ = n
}

func BenchmarkUDPGopacket(b *testing.B) {
	var eth layers.Ethernet
	var ip4 layers.IPv4
	var udp layers.UDP
	// var payload gopacket.Payload
	var dns layers.DNS

	decoded := make([]gopacket.LayerType, 0, 20)
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &udp, &dns)

	for i := 0; i < b.N; i++ {
		err := parser.DecodeLayers(UdpPacket, &decoded)
		if len(decoded) != 4 || err != nil {
			b.Error(err)
			b.FailNow()
		}
	}
}

func BenchmarkTCPGopacket(b *testing.B) {
	var eth layers.Ethernet
	var ip4 layers.IPv4
	var tcp layers.TCP

	decoded := make([]gopacket.LayerType, 0, 20)
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &tcp)

	for i := 0; i < b.N; i++ {
		err := parser.DecodeLayers(TcpPacket, &decoded)
		if len(decoded) != 3 || err != nil {
			b.Error("Something's not right")
			b.FailNow()
		}
	}
}
