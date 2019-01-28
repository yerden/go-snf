package snf

import (
	"github.com/google/gopacket"
	"syscall"
)

import "C"

// Filter interface may be applied to RingReceiver and filter
// out unneeded packets. This interface is satisfied by
// gopacket/pcap BPF object.
type Filter interface {
	Matches(ci gopacket.CaptureInfo, data []byte) bool
}

func retErr(x C.int) error {
	if x < 0 {
		return syscall.Errno(-x)
	} else if x > 0 {
		return syscall.Errno(x)
	}
	return nil
}
