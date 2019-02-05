package snf

import (
	"github.com/google/gopacket"
	"time"
)

// Filter interface may be applied to RingReceiver and filter
// out unneeded packets. This interface is satisfied by
// gopacket/pcap BPF object.
type Filter interface {
	Matches(ci gopacket.CaptureInfo, data []byte) bool
}

// Make a Filter out of a function.
type FilterFunc func(gopacket.CaptureInfo, []byte) bool

func (f FilterFunc) Matches(ci gopacket.CaptureInfo, data []byte) bool {
	return f(ci, data)
}

// Set RawFilter on the receiver. If set, the Next() and
// LoopNext() would not return until a packet matches
// filter.
//
// Hint: BPF filter from gopacket package
// satisfies Filter interface.
func (rr *RingReceiver) SetFilter(f Filter) {
	rr.SetRawFilter(RawFilterFunc(func(data []byte) bool {
		return f.Matches(rr.RecvReq().CaptureInfo(), data)
	}))
}

// Return gopacket.CaptureInfo for retrieved packet.
func (req *RecvReq) CaptureInfo() (ci gopacket.CaptureInfo) {
	ci.CaptureLength = len(req.Pkt)
	ci.InterfaceIndex = int(req.PortNum)
	ci.Length = ci.CaptureLength
	ci.Timestamp = time.Unix(0, req.Timestamp)
	return
}

var _ gopacket.ZeroCopyPacketDataSource = (*RingReceiver)(nil)
var _ gopacket.PacketDataSource = (*RingReceiver)(nil)

// Another packet retrieval capability which satisfies
// gopacket.ZeroCopyPacketDataSource interface.
func (rr *RingReceiver) ZeroCopyReadPacketData() (data []byte, ci gopacket.CaptureInfo, err error) {
	if !rr.LoopNext() {
		err = rr.Err()
	} else {
		data = rr.Data()
		ci = rr.RecvReq().CaptureInfo()
	}

	return
}

// Another packet retrieval capability which satisfies
// gopacket.PacketDataSource interface.
func (rr *RingReceiver) ReadPacketData() (data []byte, ci gopacket.CaptureInfo, err error) {
	if !rr.LoopNext() {
		err = rr.Err()
	} else {
		data = make([]byte, len(rr.Data()))
		copy(data, rr.Data())
		ci = rr.RecvReq().CaptureInfo()
	}

	return
}
