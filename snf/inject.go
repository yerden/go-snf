// Copyright 2019 Yerden Zhumabekov. All rights reserved.
//
// Use of this source code is governed by MIT license which can be
// found in the LICENSE file in the root of the source tree.

package snf

/* #include <snf.h>
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
	"io"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

// InjectStats is a sructure to return statistics from an injection
// handle.  The hardware-specific counters (nic_) apply to all
// injection handles.
type InjectStats struct {
	// Number of packets sent by this injection endpoint
	InjPktSend uint64
	// Number of total packets sent by Hardware Interface
	NicPktSend uint64
	// Number of raw bytes sent by Hardware Interface (see
	// nic_bytes_recv)
	NicBytesSend uint64
}

// InjectHandle is an opaque injection handle, allocated by
// OpenInjectHandle. There are only a limited amount of injection
// handles per NIC/port.
type InjectHandle struct {
	inj   C.snf_inject_t
	wg    sync.WaitGroup
	sigCh chan os.Signal

	// 0   handle is operational
	// 1   handle is non-operational
	//     and can only be closed
	// 2   handle is closed
	state int32
}

func makeInjectHandle(inj C.snf_inject_t) *InjectHandle {
	return &InjectHandle{
		inj:   inj,
		sigCh: make(chan os.Signal, 10)}
}

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
func OpenInjectHandle(portnum, flags int) (h *InjectHandle, err error) {
	var inj C.snf_inject_t
	err = retErr(C.snf_inject_open(C.int(portnum), C.int(flags), &inj))
	if err == nil {
		h = makeInjectHandle(inj)
		defer h.houseKeep()
	}
	return
}

func (h *InjectHandle) houseKeep() {
	wg := &h.wg

	wg.Add(1)
	go func() {
		// notify that this Handle is down
		// as soon as we're out of here
		defer wg.Done()
		for sig := range h.sigCh {
			// signal arrived
			fmt.Printf("SNF inject handle caught %v\n", sig)
			atomic.StoreInt32(&h.state, stateNotOk)
		}
		// channel closes when Close() is called
		atomic.StoreInt32(&h.state, stateClosed)
	}()
}

// SigChannel returns a channel for signal notifications.
// signal.Notify() may then be used on this channel.
//
// All consequent receiving operations on the InjectHandle will return
// io.EOF error. As a rule of thumb that means that you should halt
// all operations on this InjectHandle and gracefully exit.
func (h *InjectHandle) SigChannel() chan<- os.Signal {
	return h.sigCh
}

// Close closes injection handle and ensures that all pending sends
// are sent by the NIC.
//
// Once closed, the injection handle will have ensured that any
// pending sends have been sent out on the wire. The handle is then
// made available again for the underlying port’s limited amount of
// handles.
func (h *InjectHandle) Close() error {
	err := retErr(C.snf_inject_close(h.inj))
	if err == nil {
		// mark as closed
		signal.Stop(h.sigCh)
		close(h.sigCh)
	}

	return err
}

// GetStats gets statistics from an injection handle.
//
// This call is provided as a convenience and should not be relied on
// for time-critical applications or for high levels of accuracy.
// Statistics are only updated by the NIC periodically.
func (h *InjectHandle) GetStats() (*InjectStats, error) {
	if atomic.LoadInt32(&h.state) != stateOk {
		return nil, io.EOF
	}
	stats := &InjectStats{}
	return stats, retErr(C.snf_inject_getstats(h.inj,
		(*C.struct_snf_inject_stats)(unsafe.Pointer(stats))))
}

// GetSpeed retrieves link speed on opened injection handle.
//
// The cost of retrieving the link speed requires a function call that
// reads information kept in kernel host memory (i.e. no PCI bus
// reads).
func (h *InjectHandle) GetSpeed() (speed uint64, err error) {
	if atomic.LoadInt32(&h.state) != stateOk {
		return 0, io.EOF
	}
	err = retErr(C.snf_get_injection_speed(h.inj, (*C.ulong)(&speed)))
	return
}

// Sender object wraps SNF injection API and provides packet sending
// capabilities with some safeguarding.
type Sender struct {
	inj   C.snf_inject_t
	state *int32

	timeoutMs C.int
	flags     C.int

	// fragment buffer
	frags []C.struct_snf_pkt_fragment
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
func (h *InjectHandle) NewSender(timeout time.Duration, flags int) *Sender {
	return &Sender{
		inj:       h.inj,
		state:     &h.state,
		timeoutMs: C.int(dur2ms(timeout)),
		flags:     C.int(flags),
		frags:     make([]C.struct_snf_pkt_fragment, 100),
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
	if atomic.LoadInt32(s.state) != stateOk {
		return io.EOF
	}
	return retErr(C.snf_inject_send(s.inj, s.timeoutMs, s.flags,
		unsafe.Pointer(&pkt[0]), C.uint(len(pkt))))
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
	if atomic.LoadInt32(s.state) != stateOk {
		return io.EOF
	}
	s.checkFragBuf(len(pkt))
	hint := makeFrags(pkt, s.frags)
	return retErr(C.go_inject_send_v(s.inj, s.timeoutMs, s.flags,
		C.uintptr_t(uintptr(unsafe.Pointer(&s.frags[0]))), C.int(len(pkt)),
		hint))
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
	if atomic.LoadInt32(s.state) != stateOk {
		return io.EOF
	}
	return retErr(C.snf_inject_sched(s.inj, s.timeoutMs, s.flags,
		unsafe.Pointer(&pkt[0]), C.uint(len(pkt)), C.ulong(delayNs)))
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
	if atomic.LoadInt32(s.state) != stateOk {
		return io.EOF
	}
	s.checkFragBuf(len(pkt))
	hint := makeFrags(pkt, s.frags)
	return retErr(C.go_inject_sched_v(s.inj, s.timeoutMs, s.flags,
		C.uintptr_t(uintptr(unsafe.Pointer(&s.frags[0]))), C.int(len(pkt)),
		hint, C.ulong(delayNs)))
}
