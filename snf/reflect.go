// Copyright 2019 Yerden Zhumabekov. All rights reserved.
//
// Use of this source code is governed by MIT license which can be found in the
// LICENSE file in the root of the source tree.

package snf

// #include "wrapper.h"
import "C"

import (
	"unsafe"
)

// ReflectHandle wraps SNF reflect capability.
//
// Network packets acquired through Sniffer can be reflected back into the
// kernel path as if the device had initially sent then through to the regular
// network stack.  While Sniffer users are typically expected to process a
// significant portion of their packets with less overhead in userspace, this
// feature is provided as a convenience to allow some packets to be processed
// back in the kernel. The implementation makes no explicit step to make the
// kernel-based processing any faster than it is when Sniffer is not being used
// (in fact, it is probably much slower).
type ReflectHandle C.char

// ReflectEnable enables a network device for packet reflection and returns
// ReflectHandle.
//
// As stated in SNF documentation, this call is always a success.
func (h *Handle) ReflectEnable() (*ReflectHandle, error) {
	var ref *ReflectHandle
	return ref, retErr(C.snf_netdev_reflect_enable(handle(h),
		(*C.snf_netdev_reflect_t)(unsafe.Pointer(&ref))))
}

// Reflect a packet to the network device.
//
// pkt should hold the packet to be reflected to the network device. It should
// contain a complete Ethernet frame (without the trailing CRC) and start with
// a valid Ethernet header.
//
// As stated in SNF documentation, this call is always a success. This
// package's Reflect will return io.EOF error in case the underlying Handle is
// about to close due to signal or user Close call.
func (ref *ReflectHandle) Reflect(pkt []byte) error {
	return retErr(C.snf_netdev_reflect(C.snf_netdev_reflect_t(ref),
		unsafe.Pointer(&pkt[0]), C.uint(len(pkt))))
}
