package filter

import (
	"encoding/binary"
	// "log"
)

type TCP struct {
	// if == 0 don't use
	SrcPort, DstPort uint16

	// More scrutinized check of packet validity
	IsRigorous bool
}

const (
	EthernetHdrLen = 14
	VlanHdrLen     = 4
	MplsHdrLen     = 4
)

const (
	MacAddrLen = 6
	IPv4HdrLen = 20
	TCPHdrLen  = 20
	UDPHdrLen  = 8
)

const (
	EtherTypeIPv4 = 0x0800
	EtherTypeVlan = 0x8100
	EtherTypeIPv6 = 0x86dd
)

func PeelEthernet(p []byte) (offset int, ok bool) {
	return EthernetHdrLen, len(p) >= EthernetHdrLen
}

func EthernetSrcAddr(p []byte) (addr [MacAddrLen]byte) {
	copy(addr[:], p)
	return
}

func EthernetDstAddr(p []byte) (addr [MacAddrLen]byte) {
	copy(addr[:], p[MacAddrLen:])
	return
}

func EthernetEtherType(p []byte) (n uint16) {
	return binary.BigEndian.Uint16(p[2*MacAddrLen:])
}

func PeelVlan(p []byte) (offset int, ok bool) {
	return VlanHdrLen, len(p) >= VlanHdrLen
}

func VlanEtherType(p []byte) (n uint16) {
	return binary.BigEndian.Uint16(p)
}

func PeelMpls(p []byte) (offset int, ok bool) {
	return MplsHdrLen, len(p) >= MplsHdrLen
}

func PeelIPv4(p []byte) (offset int, ok bool) {
	if len(p) < IPv4HdrLen {
		// IPv4 header should contain at least 20 bytes
		return
	}

	var ver int
	ver, offset = int(p[0]&0xf0)>>4, int(p[0]&0xf)<<2

	if ver != 4 || offset < IPv4HdrLen {
		// mangled IPv4 version or header length
		return
	}

	// final check for total length
	return offset, len(p) >= int(binary.BigEndian.Uint16(p[2:4]))
}

func IPv4SrcAddr(p []byte, addr []byte) {
	copy(addr, p[12:16])
}

func IPv4DstAddr(p []byte, addr []byte) {
	copy(addr, p[16:20])
}

func IPv4Proto(p []byte) byte {
	return p[9]
}

func PeelTCP(p []byte) (offset int, ok bool) {
	if len(p) < TCPHdrLen {
		return
	}
	offset = int(p[12]&0xf0) >> 2
	return offset, len(p) >= offset
}

func TCPSrcPort(p []byte) uint16 {
	return binary.BigEndian.Uint16(p[0:2])
}

func TCPDstPort(p []byte) uint16 {
	return binary.BigEndian.Uint16(p[2:4])
}

func PeelUDP(p []byte) (offset int, ok bool) {
	if len(p) < UDPHdrLen {
		return
	}
	totalLen := int(binary.BigEndian.Uint16(p[4:6]))
	return UDPHdrLen, len(p) >= totalLen && totalLen >= UDPHdrLen
}

func UDPSrcPort(p []byte) uint16 {
	return binary.BigEndian.Uint16(p[0:2])
}

func UDPDstPort(p []byte) uint16 {
	return binary.BigEndian.Uint16(p[2:4])
}

func TCPPortFilter(port uint16) FilterFunc {
	return func(p []byte) int {
		offset, ok := 0, false

		if offset, ok = PeelEthernet(p); !ok {
			return 0
		}

		eth, p := p[:offset], p[offset:]
		etherType := EthernetEtherType(eth)

		// scroll all vlan tag
		for etherType == EtherTypeVlan {
			if offset, ok = PeelVlan(p); !ok {
				return 0
			}
			eth, p = p[:offset], p[offset:]
			etherType = VlanEtherType(eth)
		}

		// peel IP header
		switch etherType {
		case EtherTypeIPv6:
			// TODO:
			return 0
		case EtherTypeIPv4:
			if offset, ok = PeelIPv4(p); !ok {
				return 0
			}

			var ip []byte
			ip, p = p[:offset], p[offset:]
			if IPv4Proto(ip) != 6 { // TCP
				return 0
			}

			if offset, ok = PeelTCP(p); !ok {
				return 0
			}
		default:
			return 0
		}

		// process tcp
		tcp, p := p[:offset], p[offset:]

		if TCPSrcPort(tcp) != port && TCPDstPort(tcp) != port {
			return 0
		}

		return 1
	}
}

func UDPPortFilter(port uint16) FilterFunc {
	return func(p []byte) int {
		offset, ok := 0, false

		if offset, ok = PeelEthernet(p); !ok {
			return 0
		}

		eth, p := p[:offset], p[offset:]
		etherType := EthernetEtherType(eth)

		// scroll all vlan tag
		for etherType == EtherTypeVlan {
			if offset, ok = PeelVlan(p); !ok {
				return 0
			}
			eth, p = p[:offset], p[offset:]
			etherType = VlanEtherType(eth)
		}

		// peel IP header
		switch etherType {
		case EtherTypeIPv6:
			// TODO:
			return 0
		case EtherTypeIPv4:
			if offset, ok = PeelIPv4(p); !ok {
				return 0
			}

			var ip []byte
			ip, p = p[:offset], p[offset:]
			if IPv4Proto(ip) != 17 { // TCP
				return 0
			}

			if offset, ok = PeelUDP(p); !ok {
				return 0
			}
		default:
			return 0
		}

		// process tcp
		udp, p := p[:offset], p[offset:]

		if UDPSrcPort(udp) != port && UDPDstPort(udp) != port {
			return 0
		}

		return 1
	}
}
