// Copyright 2019 Yerden Zhumabekov. All rights reserved.
//
// Use of this source code is governed by MIT license which
// can be found in the LICENSE file in the root of the source
// tree.

package snf

import (
	"github.com/google/gopacket"
)

func getCaptureInfo(rc *RecvReq) gopacket.CaptureInfo {
	data := rc.Data()
	return gopacket.CaptureInfo{
		CaptureLength:  len(data),
		InterfaceIndex: rc.PortNum(),
		Length:         len(data),
		Timestamp:      rc.Timestamp(),
	}
}

// CaptureInfo returns gopacket.CaptureInfo metadata for retrieved
// packet.
func (req *RecvReq) CaptureInfo() (ci gopacket.CaptureInfo) {
	return getCaptureInfo(req)
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
		rc := rr.req()
		data = rc.Data()
		ci = getCaptureInfo(rc)
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
		rc := rr.req()
		data = append(data, rc.Data()...)
		ci = getCaptureInfo(rc)
	}

	return
}
