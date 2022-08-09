// Copyright 2019 Yerden Zhumabekov. All rights reserved.
//
// Use of this source code is governed by MIT license which can be
// found in the LICENSE file in the root of the source tree.

package snf

/*
#include "wrapper.h"
#include "inject.h"

int go_inject_send_v(snf_inject_t inj, int timeout_ms, int flags,
       uintptr_t frags_vec, int nfrags,
       uint32_t length_hint)
{
	return snf_inject_send_v(inj, timeout_ms, flags,
	   (struct snf_pkt_fragment *)frags_vec, nfrags,
	   length_hint);
}

int go_inject_sched_v(snf_inject_t inj, int timeout_ms, int flags,
       uintptr_t frags_vec, int nfrags,
       uint32_t length_hint, uint64_t delay_ns)
{
	return snf_inject_sched_v(inj, timeout_ms, flags,
	   (struct snf_pkt_fragment *)frags_vec, nfrags,
	   length_hint, delay_ns);
}
*/
import "C"

import (
	"fmt"
	"os"
	"time"
	"unsafe"
)

// InjectStats is a sructure to return statistics from an injection
// handle.  The hardware-specific counters (nic_) apply to all
// injection handles.
type InjectStats C.struct_snf_inject_stats

// InjPktSend returns number of packets sent by this injection endpoint.
func (s *InjectStats) InjPktSend() uint64 {
	return uint64(s.inj_pkt_send)
}

// NicPktSend returns number of total packets sent by Hardware Interface.
func (s *InjectStats) NicPktSend() uint64 {
	return uint64(s.nic_pkt_send)
}

// NicBytesSend Number of raw bytes sent by Hardware Interface (see
// nic_bytes_recv).
func (s *InjectStats) NicBytesSend() uint64 {
	return uint64(s.nic_bytes_send)
}

// type InjectHandle struct {
// inj   C.snf_inject_t
// wg    sync.WaitGroup
// sigCh chan os.Signal

// // 0   handle is operational
// // 1   handle is non-operational
// //     and can only be closed
// // 2   handle is closed
// state int32
// }

// InjectHandle is an opaque injection handle, allocated by
// OpenInjectHandle. There are only a limited amount of injection
// handles per NIC/port.
type InjectHandle C.struct_snf_inject_handle

// OpenInjectHandle opens a port for injection and allocate an
// injection handle.
//
// portnum is an index of port from 0 to N-1 where ’N’ is the number
// of Myricom ports available on the system. GetIfAddrs() may be a
// useful utility to retrieve the port number by interface name or mac
// address if there are multiple.
//
// flags are the flags for injection handle. None are currently
// defined.
//
// An injection handle is opened and allocated if the error is nil.
//
// EBUSY error means no more injection handles for this port are
// available. ENOMEM error means we ran out of memory to allocate new
// injection handle.
func OpenInjectHandle(portnum int, flags ...int) (h *InjectHandle, err error) {
	x := C.int(0)
	for _, f := range flags {
		x |= C.int(f)
	}
	var inj C.snf_inject_t
	return (*InjectHandle)(unsafe.Pointer(inj)), retErr(C.snf_inject_open(C.int(portnum), x, &inj))
}

func injHandle(inj *InjectHandle) C.snf_inject_t {
	return C.snf_inject_t(unsafe.Pointer(inj))
}

// Close closes injection handle and ensures that all pending sends
// are sent by the NIC.
//
// Once closed, the injection handle will have ensured that any
// pending sends have been sent out on the wire. The handle is then
// made available again for the underlying port’s limited amount of
// handles.
func (h *InjectHandle) Close() error {
	return retErr(C.snf_inject_close(injHandle(h)))
}

// GetStats gets statistics from an injection handle.
//
// This call is provided as a convenience and should not be relied on
// for time-critical applications or for high levels of accuracy.
// Statistics are only updated by the NIC periodically.
func (h *InjectHandle) GetStats() (*InjectStats, error) {
	stats := &InjectStats{}
	return stats, retErr(C.snf_inject_getstats(injHandle(h),
		(*C.struct_snf_inject_stats)(unsafe.Pointer(stats))))
}

// GetSpeed retrieves link speed on opened injection handle.
//
// The cost of retrieving the link speed requires a function call that
// reads information kept in kernel host memory (i.e. no PCI bus
// reads).
func (h *InjectHandle) GetSpeed() (speed uint64, err error) {
	err = retErr(C.snf_get_injection_speed(injHandle(h), (*C.ulong)(&speed)))
	return
}

// Sender object wraps SNF injection API and provides packet sending
// capabilities with some safeguarding.
type Sender struct {
	*InjectHandle
	sigCh <-chan os.Signal

	timeoutMs C.int
	flags     C.int

	// fragment buffer
	frags []C.struct_snf_pkt_fragment

	// buffers for injecting in bulk
	pkts []C.uintptr_t
	len  []C.uint32_t

	// protect the memory from GC. Sender must be allocated in heap.
	guardPkts [][]byte
}

// NewSender returns new Sender object with given timeout and flags
// for SNF injection.
//
// Timeout in milliseconds to wait if insufficient send resources are
// available to inject a new packet. Insufficient resources can be a
// lack of send descriptors or a full send queue ring. If timeout is
// 0, the function won’t block for send resources and returns EAGAIN
// error.
//
// Flags are currently not supported and should be set to 0.
func NewSender(h *InjectHandle, timeout time.Duration, flags int) *Sender {
	return &Sender{
		InjectHandle: h,
		timeoutMs:    C.int(dur2ms(timeout)),
		flags:        C.int(flags),
		frags:        make([]C.struct_snf_pkt_fragment, 100),
	}
}

// make fragments vector out of slice of slices and calculate
// overall length of packet's fragments to use as a hint for SNF
// injection API.
func makeFrags(pkt [][]byte, frags []C.struct_snf_pkt_fragment) (sz C.uint) {
	for i, data := range pkt {
		frags[i].ptr = unsafe.Pointer(&data[0])
		frags[i].length = C.uint(len(data))
		sz += frags[i].length
	}

	return sz
}

func (s *Sender) checkFragBuf(length int) {
	if d := length - len(s.frags); d > 0 {
		s.frags = append(s.frags, make([]C.struct_snf_pkt_fragment, d)...)
	}
}

// NotifyWith installs signal notification channel which is presumably
// registered via signal.Notify.
func (s *Sender) NotifyWith(ch <-chan os.Signal) {
	s.sigCh = ch
}

func (s *Sender) checkSignal() error {
	if ch := s.sigCh; ch != nil {
		select {
		case sig := <-ch:
			return fmt.Errorf("caught: %v", sig)
		default:
		}
	}
	return nil
}

// Send sends a packet and optionally block until send resources are
// available. This send function is optimized for high packet rate
// injection. While it can be coupled with a receive ring to reinject
// a packet, it is not strictly necessary. This function can be used
// as part of a packet generator. When the function returns
// successfully, the packet is guaranteed to be completely buffered by
// SNF: no references are kept to the input data and the caller is
// free to safely modify its contents. A successful return does not,
// however, guarantee that the packet has been injected into the
// network. The SNF implementation may choose to hold on to the packet
// for coalescing in order to improve packet throughput.
//
// Packet must hold a complete Ethernet frame (without the trailing
// CRC) and start with a valid Ethernet header. The hardware will
// append 4-CRC bytes at the end of the packet. The maximum valid
// packet size is 9000 bytes and is enforced by the library. The
// minimum valid packet size is 60 bytes, although any packet smaller
// than 60 bytes will be accepted by the library and padded by the
// hardware.
//
// EAGAIN error will be returned in case there are insufficient
// resources to send packet. If timeout is non-zero, the caller will
// have blocked at least that many milliseconds before resources could
// become available.
//
// EINVAL error will be returned in case packet length is larger than
// 9000 bytes.
//
// If successful, the packet is completely buffered for sending by
// SNF. The implementation guarantees that it will eventually send the
// packet out in a timely fashion without requiring further calls into
// SNF.
func (s *Sender) Send(pkt []byte) error {
	if err := s.checkSignal(); err != nil {
		return err
	}
	return retErr(C.snf_inject_send(injHandle(s.InjectHandle), s.timeoutMs,
		s.flags, unsafe.Pointer(&pkt[0]), C.uint(len(pkt))))
}

// SendBulk sends packets in bulk using snf_inject_send. If there are errors, it
// will return the first error found, or nil.
func (s *Sender) SendBulk(pkts [][]byte) error {
	if err := s.checkSignal(); err != nil {
		return err
	}

	s.guardPkts = pkts
	s.pkts = s.pkts[:0]
	s.len = s.len[:0]
	for _, pkt := range pkts {
		s.pkts = append(s.pkts, C.uintptr_t(uintptr(unsafe.Pointer(&pkt[0]))))
		s.len = append(s.len, C.uint32_t(len(pkt)))
	}

	return retErr(C.snf_inject_send_bulk(injHandle(s.InjectHandle), s.timeoutMs, s.flags,
		&s.pkts[0], C.uint32_t(len(s.pkts)), &s.len[0]))
}

// SendVec sends a packet assembled from a vector of fragments and
// optionally block until send resources are available. This send
// function follows the same semantics as Send except that the packet
// to be injected can be assembled from multiple fragments (or
// buffers).
//
// Packet should hold 1 or more buffers/fragments that can be used to
// compose a complete Ethernet frame (not including the trailing CRC
// header). The first fragment must point to a valid Ethernet header
// and the hardware will append its own (valid 4-byte CRC) at the end
// of the last buffer/fragment passed in pkt. When all the fragments
// are added up, the maximum valid packet size is 9000 bytes and is
// enforced by the library.  The minimum valid packet size is 60
// bytes, although any packet smaller than 60 bytes will be accepted
// by the library and padded by the hardware.
//
// EAGAIN error will be returned in case there are insufficient
// resources to send packet. If timeout is non-zero, the caller will
// have blocked at least that many milliseconds before resources could
// become available.
//
// EINVAL error will be returned in case overall fragments length is
// larger than 9000 bytes.
//
// If successful, the packet is completely buffered for sending by
// SNF. The implementation guarantees that it will eventually send the
// packet out in a timely fashion without requiring further calls into
// SNF.
func (s *Sender) SendVec(pkt ...[]byte) error {
	if err := s.checkSignal(); err != nil {
		return err
	}
	s.checkFragBuf(len(pkt))
	hint := makeFrags(pkt, s.frags)
	return retErr(C.go_inject_send_v(injHandle(s.InjectHandle), s.timeoutMs,
		s.flags, C.uintptr_t(uintptr(unsafe.Pointer(&s.frags[0]))),
		C.int(len(pkt)), hint))
}

// Sched sends a packet with hardware delay and optionally blocks
// until send resources are available. This send function is used for
// paced packet injection. This function can be used as part of a
// packet replay program. When the function returns successfully, the
// packet is guaranteed to be completely buffered by SNF: no
// references are kept to the input data and the caller is free to
// safely modify its contents. The SNF implementation delays
// transmitting the packet according to the delayNs parameter,
// relative to the start of the prior packet.
//
// Packet must hold a complete Ethernet frame (without the trailing
// CRC) and start with a valid Ethernet header. The hardware will
// append 4-CRC bytes at the end of the packet. The maximum valid
// packet size is 9000 bytes and is enforced by the library. The
// minimum valid packet size is 60 bytes, although any packet smaller
// than 60 bytes will be accepted by the library and padded by the
// hardware.
//
// delayNs is the minimum delay between the start of the prior packet
// and the start of this packet. Packets with a delay less than the
// time to send the prior packet are send immediately.  It is
// recommended to use 0 as the delta on the first packet sent.
//
// EAGAIN error will be returned in case there are insufficient
// resources to send packet. If timeout is non-zero, the caller will
// have blocked at least that many milliseconds before resources could
// become available.
//
// EINVAL error will be returned in case packet length is larger than
// 9000 bytes.
//
// ENOTSUP error will be returned in case hardware doesnt support
// injection pacing.
//
// If successful, the packet is completely buffered for sending by
// SNF. The implementation guarantees that it will eventually send the
// packet out, as scheduled, without requiring further calls into SNF.
func (s *Sender) Sched(delayNs int64, pkt []byte) error {
	if err := s.checkSignal(); err != nil {
		return err
	}
	return retErr(C.snf_inject_sched(injHandle(s.InjectHandle), s.timeoutMs,
		s.flags, unsafe.Pointer(&pkt[0]), C.uint(len(pkt)), C.ulong(delayNs)))
}

// SchedVec sends a packet assembled from a vector of fragments at a
// scheduled point relative to the start of the prior packet and
// optionally block until send resources are available.  This send
// function follows the same semantics as Sched except that the packet
// to be injected can be assembled from multiple fragments (or
// buffers).
//
// Packet should hold 1 or more buffers/fragments that can be used to
// compose a complete Ethernet frame (not including the trailing CRC
// header). The first fragment must point to a valid Ethernet header
// and the hardware will append its own (valid 4-byte CRC) at the end
// of the last buffer/fragment passed in pkt. When all the fragments
// are added up, the maximum valid packet size is 9000 bytes and is
// enforced by the library.  The minimum valid packet size is 60
// bytes, although any packet smaller than 60 bytes will be accepted
// by the library and padded by the hardware.
//
// delayNs is the minimum delay between the start of the prior packet
// and the start of this packet. Packets with a delay less than the
// time to send the prior packet are send immediately.  It is
// recommended to use 0 as the delta on the first packet sent.
//
// EAGAIN error will be returned in case there are insufficient
// resources to send packet. If timeout is non-zero, the caller will
// have blocked at least that many milliseconds before resources could
// become available.
//
// EINVAL error will be returned in case packet length is larger than
// 9000 bytes.
//
// ENOTSUP error will be returned in case hardware doesnt support
// injection pacing.
//
// If successful, the packet is completely buffered for sending by
// SNF. The implementation guarantees that it will eventually send the
// packet out, as scheduled, without requiring further calls into SNF.
func (s *Sender) SchedVec(delayNs int64, pkt ...[]byte) error {
	if err := s.checkSignal(); err != nil {
		return err
	}
	s.checkFragBuf(len(pkt))
	hint := makeFrags(pkt, s.frags)
	return retErr(C.go_inject_sched_v(injHandle(s.InjectHandle), s.timeoutMs,
		s.flags, C.uintptr_t(uintptr(unsafe.Pointer(&s.frags[0]))), C.int(len(pkt)),
		hint, C.ulong(delayNs)))
}
