// Copyright 2019 Yerden Zhumabekov. All rights reserved.
//
// Use of this source code is governed by MIT license which
// can be found in the LICENSE file in the root of the source
// tree.

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

// FilterFunc implements Filter interface.
type FilterFunc func(gopacket.CaptureInfo, []byte) bool

// Matches returns if a packet with its metadata matches
// filter condition.
func (f FilterFunc) Matches(ci gopacket.CaptureInfo, data []byte) bool {
	return f(ci, data)
}

// SetFilter Sets a Filter on the receiver. If set, the Next() and
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

// CaptureInfo returns gopacket.CaptureInfo metadata for retrieved packet.
func (req *RecvReq) CaptureInfo() (ci gopacket.CaptureInfo) {
	ci.CaptureLength = len(req.Pkt)
	ci.InterfaceIndex = int(req.PortNum)
	ci.Length = ci.CaptureLength
	ci.Timestamp = time.Unix(0, req.Timestamp)
	return
}

var _ gopacket.ZeroCopyPacketDataSource = (*RingReceiver)(nil)
var _ gopacket.PacketDataSource = (*RingReceiver)(nil)

// ZeroCopyReadPacketData reads next packet from receiver and returns
// packet data, gopacket.CaptureInfo metadata and possibly error.
// This satisfies gopacket.ZeroCopyPacketDataSource interface.
func (rr *RingReceiver) ZeroCopyReadPacketData() (data []byte, ci gopacket.CaptureInfo, err error) {
	if !rr.LoopNext() {
		err = rr.Err()
	} else {
		data = rr.Data()
		ci = rr.RecvReq().CaptureInfo()
	}

	return
}

// ReadPacketData reads next packet from receiver and returns
// packet data, gopacket.CaptureInfo metadata and possibly error.
// This satisfies gopacket.PacketDataSource interface.
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
