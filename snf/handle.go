package snf

/*
#cgo CFLAGS: -I/opt/snf/include
#cgo LDFLAGS: -L/opt/snf/lib -lsnf
#include <snf.h>
#include "wrapper.h"
*/
import "C"

import (
	"unsafe"
)

// Handle encapsulates a device handle.
type Handle C.struct_snf_handle

// snf_open() options container
type handlerOpts struct {
	numRings     C.int
	rss          *C.struct_snf_rss_params
	flags        C.int
	dataRingSize C.long
}

// HandlerOption specifies an option for opening a Handle.
type HandlerOption struct {
	f func(*handlerOpts)
}

// CHashFunc is the C implementation of hash function.
type CHashFunc C.rss_hash_fn

// OpenHandle opens a port for sniffing and allocates a device handle
// with specified options. See documentation for various options to
// see their applicability. None of the options is mandatory; if
// omitted default settings will be applied.
//
// portnum can be interpreted as an integer for a specific port number
// or as a mask when AggregatePortMask is specified in flags option.
// Port information can be obtained through GetIfAddrs() and
// active/valid masks are available with PortMask() method. As a
// special case, if portnum -1 is passed, the library will internally
// open a portmask as in valid mask returned in PortMask().
//
// The function returns a Handle object and a possible error. If error
// is nil the port is opened and a device handle is allocated (see
// remarks). In this case, the NIC switches from Ethernet mode to
// Capture mode and the Ethernet driver stops receiving packets.  If
// successful, a call to Start() is required to the Sniffer-mode NIC
// to deliver packets to the host, and this call must occur after at
// least one ring is opened (OpenRing() method).
//
// Possible errors include:
//
// EBUSY: Device is already opened.
//
// EINVAL: Invalid argument passed, most probably num_rings (if not, check
// syslog).
//
// E2BIG: Driver could not allocate requested dataring_sz (check syslog).
//
// ENOMEM: Either library or driver did not have enough memory to allocate
// handle descriptors (but not data ring).
//
// ENODEV: Device portnum can't be opened.
func OpenHandle(portnum uint32, options ...HandlerOption) (*Handle, error) {
	var dev C.snf_handle_t
	opts := &handlerOpts{
		numRings:     0,
		dataRingSize: 0,
		rss:          nil,
		flags:        -1,
	}

	for _, opt := range options {
		opt.f(opts)
	}

	rc := C.snf_open(C.uint(portnum), opts.numRings, opts.rss,
		opts.dataRingSize, opts.flags, &dev)
	return (*Handle)(unsafe.Pointer(dev)), retErr(rc)
}

// HandlerOptNumRings specifies number of rings to allocate for
// receive-side scaling feature, which determines how many different
// threads can open their own ring via OpenRing(). If not specified or
// set to 0 or less than zero, default value is used unless
// SNF_NUM_RINGS is set in the environment.
func HandlerOptNumRings(n int) HandlerOption {
	return HandlerOption{func(opts *handlerOpts) {
		opts.numRings = C.int(n)
	}}
}

// HandlerOptDataRingSize specifies the total amount of memory to be
// used to store incoming packet data for *all* rings to be opened. If
// the value is set to 0 or less than 0, the library tries to choose a
// sensible default unless SNF_DATARING_SIZE is set in the
// environment.  The value can be specified in megabytes (if it is
// less than 1048576) or is otherwise considered to be in bytes.  In
// either case, the library may slightly adjust the user's request to
// satisfy alignment requirements (typically 2MB boundaries).
func HandlerOptDataRingSize(n int64) HandlerOption {
	return HandlerOption{func(opts *handlerOpts) {
		opts.dataRingSize = C.long(n)
	}}
}

// HandlerOptFlags specifies a mask of flags documented in SNF API
// Reference.  You may specify a number of flags. They will be OR'ed
// before applying to the Handle.
func HandlerOptFlags(flags int) HandlerOption {
	return HandlerOption{func(opts *handlerOpts) {
		if flags < 0 {
			opts.flags = -1
		} else if opts.flags < 0 {
			opts.flags = C.int(flags)
		} else {
			opts.flags |= C.int(flags)
		}
	}}
}

// HandlerOptRssFlags specifies RSS flags to use by RSS mechanism. By
// default, the implementation will select its own mechanism to divide
// incoming packets across rings. This parameter is only meaningful
// if there are more than 1 rings to be opened.
//
// Note that this option unsets HandlerOptRssFunc option.
func HandlerOptRssFlags(flags int) HandlerOption {
	return HandlerOption{func(opts *handlerOpts) {
		if opts.rss == nil {
			opts.rss = &C.struct_snf_rss_params{}
		}
		C.add_rss_flags(opts.rss, C.int(flags))
	}}
}

// HandlerOptRssFunc specifies custom hash function to use by RSS
// mechanism. By default, the implementation will select its own
// mechanism to divide incoming packets across rings. This parameter
// is only meaningful if there are more than 1 rings to be opened.
//
// fn should comply with the following C function prototype:
//   int (*rss_hash_fn)(struct snf_recv_req *r, void *context, uint32_t *hashval);
// ctx is an opaque context.
//
// fn is a hash function provided by user as a pointer to C function.  The
// callback is provided with a valid snf_recv_req structure which contains a
// packet as received by Sniffer. It is up to the user to inspect and parse the
// packet to produce a unique 32-bit hash. The implementation will map the
// 32-bit into one of the rings allocated in snf_open.  The function must
// return one of three values:
//
// 0: The packet is queued in the ring based on the 32-bit hash value that is
// provided, which is hashval%num_rings.
//
// <0: The packet is dropped and accounted as a drop in the ring corresponding
// to the 32-bit hash value provided by the user.  fn is the pointer to Cgo
// function and ctx is the pointer to that function context.
//
// Please be aware that applying custom hash function may impose some
// overhead on the hot path.
//
// Note that this option unsets HandlerOptRssFlags option.
func HandlerOptRssFunc(fn *CHashFunc, ctx unsafe.Pointer) HandlerOption {
	return HandlerOption{func(opts *handlerOpts) {
		opts.rss = &C.struct_snf_rss_params{}
		C.set_rss_func(opts.rss, (*C.rss_hash_fn)(unsafe.Pointer(fn)), ctx)
	}}
}

func handle(h *Handle) C.snf_handle_t {
	return C.snf_handle_t(unsafe.Pointer(h))
}

// LinkState gets link status on opened handle.
//
// Returns one of LinkDown or LinkUp.
//
// The cost of retrieving the link state requires a function call
// that reads state kept in kernel host memory (i.e. no PCI bus
// reads).
func (h *Handle) LinkState() (int, error) {
	out := C.get_link_state(handle(h))
	return intErr(&out)
}

// LinkSpeed gets link speed on opened handle.
//
// Returns speed in bits-per-second for the link.
//
// The cost of retrieving the link state requires a function call
// that reads state kept in kernel host memory (i.e. no PCI bus
// reads).
func (h *Handle) LinkSpeed() (uint64, error) {
	out := C.get_link_speed(handle(h))
	return uint64Err(&out)
}

// Start packet capture on a port.  Packet capture is only started if
// it is currently stopped or has not yet started for the first time.
//
// It is safe to restart packet capture via Start() and Stop()
// methods.  This call must be called before any packet can be
// received.
func (h *Handle) Start() error {
	return retErr(C.snf_start(handle(h)))
}

// Stop packet capture on a port.  This function should be used
// carefully in multi-process mode as a single stop command stops
// packet capture on all rings.  It is usually best to simply Close()
// a ring to stop capture on a ring.
//
// Stop instructs the NIC to drop all packets until the next Start()
// or until the port is closed.  The NIC only resumes delivering
// packets when the port is closed, not when traffic is stopped.
func (h *Handle) Stop() error {
	return retErr(C.snf_stop(handle(h)))
}

// Close port.
//
// This function can be closed once all opened rings (if any) are
// closed through ring's Close() method.  Once a port is determined to
// be closable, it is implicitly called as if a call had been
// previously made to Stop() method.
//
// EBUSY is returned if some rings are still opened and the port
// cannot be closed (yet).
//
// If successful, all resources allocated at open time are unallocated
// and the device switches from Sniffer mode to Ethernet mode such
// that the Ethernet driver resumes receiving packets.
func (h *Handle) Close() (err error) {
	// if EBUSY, you should close other rings
	return retErr(C.snf_close(handle(h)))
}

// OpenRing opens the next available ring.
//
// Ring handle allocated if the call is successful.
//
// EBUSY is returned if too many rings already opened.
//
// This function will consider the value of the SNF_RING_ID
// environment variable.  For more control over ring allocation,
// consider using OpenRingID() method instead.
//
// Please be sure that you close the ring once you've done working on
// it. Leaking rings may lead to packet drops in neighbour
// applications working on the same NIC.
//
// If successful, a call to Start() method is required to the
// Sniffer-mode NIC to deliver packets to the host.
func (h *Handle) OpenRing() (ring *Ring, err error) {
	// from the description of snf_ring_open_id() function,
	// if the id argument is -1 it "behaves as if snf_ring_open()
	// was called"
	return h.OpenRingID(-1)
}

// OpenRingID opens a ring from an opened port.
//
// ring_id Ring number to open, from 0 to num_rings - 1. If the value
// is -1, this function behaves as if OpenRing() was called.
//
// Ring handle allocated if the call is successful.
//
// EBUSY is returned if id == -1, Too many rings already opened.  if
// id >= 0, that ring is already opened.
//
// Unlike OpenRing(), this function ignores the environment variable
// SNF_RING_ID since the expectation is that users want to directly
// control ring allocation (unlike through libpcap).
//
// Please be sure that you close the ring once you've done working on
// it. Leaking rings may lead to packet drops in neighbour
// applications working on the same NIC.
//
// If successful, a call to Handle's Start() is required to the
// Sniffer-mode NIC to deliver packets to the host.
func (h *Handle) OpenRingID(id int) (ring *Ring, err error) {
	var r C.snf_ring_t
	rc := C.snf_ring_open_id(handle(h), C.int(id), &r)
	return (*Ring)(unsafe.Pointer(r)), retErr(rc)
}

// TimeSourceState returns timesource information from opened handle
//
// Returns one of Timesource state constants.
//
// The cost of retrieving the timesource state requires a function
// call that reads state kept in kernel host memory (i.e. no PCI bus
// reads).
func (h *Handle) TimeSourceState() (int, error) {
	out := C.get_timesource_state(handle(h))
	return intErr(&out)
}
