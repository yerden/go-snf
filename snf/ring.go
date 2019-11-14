package snf

/*
#cgo CFLAGS: -I/opt/snf/include
#cgo LDFLAGS: -L/opt/snf/lib -lsnf -lpcap
#include <snf.h>
#include "wrapper.h"
*/
import "C"

import (
	"time"
	"unsafe"
)

// Ring encapsulates a device's ring handle.
type Ring C.struct_snf_ring

// RingPortInfo is a receive ring information.
type RingPortInfo C.struct_snf_ring_portinfo

// Ring returns a physical ring which may be a part of aggregated
// ring.
func (pi *RingPortInfo) Ring() *Ring {
	return (*Ring)(unsafe.Pointer(pi.ring))
}

// QueueSize returns size of the data queue.
func (pi *RingPortInfo) QueueSize() uintptr {
	return uintptr(pi.q_size)
}

// PortCnt returns how many physical ports deliver to this receive
// ring.
func (pi *RingPortInfo) PortCnt() uint32 {
	return uint32(pi.portcnt)
}

// PortMask returns which ports deliver to this receive ring.
func (pi *RingPortInfo) PortMask() uint32 {
	return uint32(pi.portmask)
}

// Data returns underlying array of data for receive ring.
func (pi *RingPortInfo) Data() []byte {
	return array2Slice(uintptr(pi.data_addr), int(pi.data_size))
}

// RingQInfo is a queue consumption information.
type RingQInfo C.struct_snf_ring_qinfo

// Avail returns amount of data available not yet received
// (approximate).
func (qinfo *RingQInfo) Avail() uintptr {
	return uintptr(qinfo.q_avail)
}

// Borrowed returns amount of data currently borrowed (exact).
func (qinfo *RingQInfo) Borrowed() uintptr {
	return uintptr(qinfo.q_borrowed)
}

// Free returns amount of free space still available (approximate).
func (qinfo *RingQInfo) Free() uintptr {
	return uintptr(qinfo.q_free)
}

// RingStats is a structure to return statistics from a ring.  The Hardware-specific
// counters apply to all rings as they are counted before any
// demultiplexing to a ring is applied.
type RingStats struct {
	// Number of packets received by Hardware Interface
	NicPktRecv uint64
	// Number of packets dropped by Hardware Interface
	NicPktOverflow uint64
	// Number of Bad CRC/PHY packets seen by Hardware Interface
	NicPktBad uint64
	// Number of packets received into the receive ring
	RingPktRecv uint64
	// Number of packets dropped because of insufficient space in receive ring
	RingPktOverflow uint64
	// Number of raw bytes received by the Hardware Interface on
	// all rings. Each Ethernet data packet includes 8 bytes of HW
	// header, 4 bytes of CRC and the result is aligned to 16 bytes
	// such that a minimum size 60 byte packet counts for 80 bytes.
	NicBytesRecv uint64
	// Number of packets dropped because of insufficient space in
	// shared SNF buffering.
	SnfPktOverflow uint64
	// Number of packets droped, reflected in Packets Drop Filter
	//in Counters.
	NicPktDropped uint64
}

func ring(r *Ring) C.snf_ring_t {
	return C.snf_ring_t(unsafe.Pointer(r))
}

// Close a ring
//
// This function is used to inform the underlying device that no
// further calls to Recv() will be made.  If the device is not
// subsequently closed (Handle's Close()), all packets that would have
// been delivered to this ring are dropped.  Also, by calling this
// function, users confirm that all packet processing for packets
// obtained on this ring via ring's Recv() is complete.
//
// Returns 0 (successful).
//
// The user has processed the last packet obtained with Recv() and
// such and the device can safely be closed via Handle's Close() if
// all other rings are also closed.  All packet data memory returned
// by Ring or RingReceiver is reclaimed by SNF API and cannot be
// dereferenced.
func (r *Ring) Close() error {
	return retErr(C.snf_ring_close(ring(r)))
}

// Stats returns statistics from a receive ring.
//
// This call is provided as a convenience and should not be relied on
// for time-critical applications or for high levels of accuracy.
// Statistics are only updated by the NIC periodically.
//
// Administrative clearing of NIC counters while a Sniffer-based
// application is running may cause some of the counters to be
// incorrect.
func (r *Ring) Stats() (*RingStats, error) {
	stats := &RingStats{}
	return stats, retErr(C.snf_ring_getstats(ring(r),
		(*C.struct_snf_ring_stats)(unsafe.Pointer(stats))))
}

// PortInfo returns information for the ring.
// For aggregated rings, returns information for each of the physical
// rings.
func (r *Ring) PortInfo() ([]RingPortInfo, error) {
	var count C.int
	if err := retErr(C.snf_ring_portinfo_count(ring(r), &count)); err != nil {
		return nil, err
	}

	pi := make([]RingPortInfo, count)
	return pi, retErr(C.snf_ring_portinfo(ring(r),
		(*C.struct_snf_ring_portinfo)(unsafe.Pointer(&pi[0]))))
}

// Recv receives next packet from a receive ring.
//
// This function is used to return the next available packet in a
// receive ring.  The function can block indefinitely, for a specific
// timeout or be used as a non-blocking call with a timeout of 0.
//
// timeout is a receive timeout to control how the function blocks for
// the next packet. If the value is less than 0, the function can
// block indefinitely.  If the value is 0, the function is guaranteed
// to never enter a blocking state and returns EAGAIN unless there is
// a packet waiting.  If the value is greater than 0, the caller
// indicates a desired wait time in milliseconds.  With a non-zero
// wait time, the function only blocks if there are no outstanding
// packets.  If the timeout expires before a packet can be received,
// the function returns EAGAIN (and not ETIMEDOUT).  In all cases,
// users should expect that the function may return EINTR as the
// result of signal delivery.
//
// req is a Receive Packet structure, only updated when the function
// returns 0 for a successful packet receive (RecvReq).
//
// Return values: nil is a successful packet delivery, req is updated
// with packet information. EINTR means the call was interrupted by a
// signal handler. EAGAIN means that no packets are available (only
// when timeout is >= 0).
//
// The returned packet always points directly into the receive ring
// where the NIC has DMAed the packet (there are no copies).  As such,
// the user obtains a pointer to library/driver allocated memory.
// Users can modify the contents of the packets but should remain
// within the slice boundaries.
//
// Upon calling the function, the library assumes that the user is
// done processing the previous packet.  The same assumption is made
// when the ring is closed (ring's Close() method).
func (r *Ring) Recv(timeout time.Duration, req *RecvReq) error {
	return retErr(C.snf_ring_recv(ring(r), dur2ms(timeout), (*C.struct_snf_recv_req)(req)))
}

// RecvMany receives new packets from the ring following
// borrow-many-return-many receive model.
//
// timeout semantics is as in Recv() method.
//
// reqs is an array of user-allocated RecvReq structs which will be
// filled with received packets descriptors.
//
// If qinfo is not nil, the struct will be filled with queue
// consumption information.
//
// The output of this function is the actual number of descriptors
// filled in reqs and an error if any.
func (r *Ring) RecvMany(timeout time.Duration, reqs []RecvReq, qinfo *RingQInfo) (int, error) {
	qi := (*C.struct_snf_ring_qinfo)(qinfo)
	out := C.ring_recv_many(ring(r), dur2ms(timeout),
		(*C.struct_snf_recv_req)(&reqs[0]), C.int(len(reqs)), qi)
	return intErr(&out)
}

// ReturnMany returns memory of given packets back to the data ring.
// Please be aware SNF API returns queued data with no regard to
// supplied packets, i.e. in FIFO way.
//
// Error is returned in case snf_ring_return_many() was unsuccessful.
func (r *Ring) ReturnMany(reqs []RecvReq, qinfo *RingQInfo) error {
	datalen := C.uint(0)
	for i := range reqs {
		datalen += reqs[i].length_data
	}

	if datalen == 0 {
		return nil
	}

	qi := (*C.struct_snf_ring_qinfo)(qinfo)
	return retErr(C.snf_ring_return_many(ring(r), datalen, qi))
}
