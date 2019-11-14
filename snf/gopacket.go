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

func reqDataCi(req *RecvReq) (data []byte, ci gopacket.CaptureInfo) {
	data = req.Data()
	return data, gopacket.CaptureInfo{
		CaptureLength:  len(data),
		InterfaceIndex: req.PortNum(),
		Length:         len(data),
		Timestamp:      time.Unix(0, req.Timestamp()),
	}
}

// CaptureInfo returns gopacket.CaptureInfo metadata for retrieved
// packet.
func (req *RecvReq) CaptureInfo() (ci gopacket.CaptureInfo) {
	_, ci = reqDataCi(req)
	return
}

var _ gopacket.ZeroCopyPacketDataSource = (*RingReader)(nil)
var _ gopacket.PacketDataSource = (*RingReader)(nil)

// ZeroCopyReadPacketData implements gopacket.ZeroCopyPacketDataSource.
func (rr *RingReader) ZeroCopyReadPacketData() (data []byte, ci gopacket.CaptureInfo, err error) {
	if !rr.LoopNext() {
		err = rr.Err()
	} else {
		data, ci = reqDataCi(rr.req())
	}

	return
}

// ReadPacketData implements gopacket.PacketDataSource.
func (rr *RingReader) ReadPacketData() (data []byte, ci gopacket.CaptureInfo, err error) {
	if data, ci, err = rr.ZeroCopyReadPacketData(); err == nil {
		data = append(make([]byte, 0, len(data)), data...)
	}
	return
}
