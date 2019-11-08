// Copyright 2019 Yerden Zhumabekov. All rights reserved.
//
// Use of this source code is governed by MIT license which
// can be found in the LICENSE file in the root of the source
// tree.

/*
Package snf is a wrapper for SNF library to support direct interaction
with Myricom/CSPI boards.

The purpose of the package is to avoid using libpcap-wrapped SNF
functionality in favor of more flexible and full-featured SNF C
binding. Hence it diminishes (but not fully negates, see below)
dependency on libpcap library.

In order to be able to use google/gopacket (layers etc.)
functionality, some interfaces in those packages are satisfied. Any
feature requests regarding extension of such integration are welcomed.

Most part of the package is a pretty much straightforward SNF API
wrappers. On top of that, RingReceiver is provided which wraps bulk
packet operation. RingReceiver also satisfies
gopacket.ZeroCopyPacketDataSource in case you work with
google/gopacket/pcap.

The package utilizes BPF virtual machine from libpcap. Since original
SNF API doesn't expose any filtering service RingReceiver object
provides SetBPF method to apply offline BPF filtering.

It is extremely important from the system point of view that all the
rings and handles are properly closed upon program exit. Thus, some
work was done to handle signals in this library with minimal
intrusion. It is programmer's choice of whether to use this package's
signal handling or devise a custom one.

Some examples are provided to show various use cases, features,
limitations and so on.
*/
package snf

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/signal"
	"reflect"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

/*
#cgo CFLAGS: -I/opt/snf/include
#cgo LDFLAGS: -L/opt/snf/lib -lsnf -lpcap
#include <snf.h>

void set_rss_flags(struct snf_rss_params *rss, int flags) {
  rss->mode = SNF_RSS_FLAGS;
  rss->params.rss_flags = flags;
}

void set_rss_func(struct snf_rss_params *rss, void *fn, void *ctx)
{
  rss->mode = SNF_RSS_FUNCTION;
  rss->params.rss_function.rss_hash_fn = fn;
  rss->params.rss_function.rss_context = ctx;
}

struct recv_many_out {
	int nreq_out;
	int rc;
};

struct recv_many_out recv_many(
	snf_ring_t ring,
	int timeout_ms,
	struct snf_recv_req *req_vector,
	int nreq_in,
	struct snf_ring_qinfo *qinfo)
{
	struct recv_many_out out;
	out.rc = snf_ring_recv_many(ring, timeout_ms, req_vector, nreq_in, &out.nreq_out, qinfo);
	return out;
}
*/
import "C"

// SNF API version number (16 bits).
//
// Least significant byte increases for minor backwards compatible
// changes in the API. Most significant byte increases for
// incompatible changes in the API.
const (
	Version uint16 = C.SNF_VERSION_API
)

// Underlying port's state (DOWN or UP)
const (
	// Link is down.
	LinkDown int = C.SNF_LINK_DOWN
	// Link is up.
	LinkUp = C.SNF_LINK_UP
)

// Timesource state (for SYNC NICs)
const (
	// Local timesource (no external).
	// Returned if there is no available external
	// timesource or if its use was explicitly disabled.
	TimeSourceLocal int = C.SNF_TIMESOURCE_LOCAL

	// External Timesource: not synchronized (yet)
	TimeSourceExtUnsynced = C.SNF_TIMESOURCE_EXT_UNSYNCED

	// External Timesource: synchronized
	TimeSourceExtSynced = C.SNF_TIMESOURCE_EXT_SYNCED

	// External Timesource: NIC failure to connect to source
	TimeSourceExtFailed = C.SNF_TIMESOURCE_EXT_FAILED

	// Arista switch is sending ptp timestamps
	TimeSourceAristaActive = C.SNF_TIMESOURCE_ARISTA_ACTIVE

	// PPS is being used for time
	TimeSourcePPS = C.SNF_TIMESOURCE_PPS
)

// RSS parameters for SNF_RSS_FLAGS, flags that can be
// specified to let the implementation know which fields
// are significant when generating the hash. By default, RSS
// is computed on IPv4/IPv6 addresses and source/destination
// ports when the protocol is TCP or UDP or SCTP, for
// example, "RssIP | RssSrcPort | RssDstPort" means IP
// addresses and TCP/UDP/SCTP ports will be applied in the
// hash.
const (
	// Include IP (v4 or v6) SRC/DST addr in hash
	RssIP int = C.SNF_RSS_IP
	// Include TCP/UDP/SCTP SRC port in hash
	RssSrcPort = C.SNF_RSS_SRC_PORT
	// Include TCP/UDP/SCTP DST port in hash
	RssDstPort = C.SNF_RSS_DST_PORT
	// Include GTP TEID in hash
	RssGtp = C.SNF_RSS_GTP
	// Include GRE contents in hash
	RssGre = C.SNF_RSS_GRE
)

// Open flags for process-sharing, port aggregation and packet
// duplication.  Used when opening a Handle with HandlerOptFlags
// option.
const (
	// PShared flag states that device can be process-sharable. This
	// allows multiple independent processes to share rings on the
	// capturing device. This option can be used to design a custom
	// capture solution but is also used in libpcap when multiple
	// rings are requested. In this scenario, each libpcap device
	// sees a fraction of the traffic if multiple rings are used
	// unless the RxDuplicate option is used, in which case each
	// libpcap device sees the same incoming packets.
	PShared = C.SNF_F_PSHARED
	// AggregatePortMask shows that device can be opened for port
	// aggregation (or merging). When this flag is passed, the portnum
	// parameter in OpenHandleWithOpts() is interpreted as a bitmask
	// where each set bit position represents a port number. The
	// Sniffer library will then attempt to open every portnum with
	// its bit set in order to merge the incoming data to the user
	// from multiple ports. Subsequent calls to OpenRing() return a
	// ring handle that internally opens a ring on all underlying
	// ports.
	AggregatePortMask = C.SNF_F_AGGREGATE_PORTMASK
	// RxDuplicate shows that device can duplicate packets to multiple
	// rings as opposed to applying RSS in order to split incoming
	// packets across rings. Users should be aware that with N rings
	// opened, N times the link bandwidth is necessary to process
	// incoming packets without drops. The duplication happens in the
	// host rather than the NIC, so while only up to 10Gbits of
	// traffic crosses the PCIe, N times that bandwidth is necessary
	// on the host.
	//
	// When duplication is enabled, RSS options are ignored since
	// every packet is delivered to every ring.
	RxDuplicate = C.SNF_F_RX_DUPLICATE
)

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

// IfAddrs is a structure to map Interfaces to Sniffer port numbers.
type IfAddrs struct {
	// interface name, as in ifconfig
	Name string
	// snf port number
	PortNum uint32
	// Maximum RX rings supported
	MaxRings int
	// MAC address
	MACAddr [6]byte
	// Maximum TX injection handles supported
	MaxInject int
	// Underlying port's state (DOWN or UP)
	LinkState int
	// Link Speed (bps)
	LinkSpeed uint64
}

// RingPortInfo is a receive ring information.
type RingPortInfo struct {
	// Single ring
	Ring unsafe.Pointer
	// Size of the data queue
	QSize uintptr
	// How many physical ports deliver to this receive ring
	PortCnt uint32
	// Which ports deliver to this receive ring
	Portmask uint32
	// Ring data
	Data []byte
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

// RecvReq is a descriptor of a packet received on a data ring.
type RecvReq C.struct_snf_recv_req

// Data returns data payload of the packet as a pointer directly in
// the given data ring.
//
// User may not retain the slice returned by Data since the underlying
// memory chunk may be reused.
func (req *RecvReq) Data() (data []byte) {
	sh := (*reflect.SliceHeader)(unsafe.Pointer(&data))
	sh.Data = uintptr(req.pkt_addr)
	sh.Len = int(req.length)
	sh.Cap = int(req.length_data)
	return
}

// TimestampNs() returns 64-bit timestamp in nanoseconds.
func (req *RecvReq) TimestampNs() int64 {
	return int64(req.timestamp)
}

// Timestamp() returns timestamp of a packet.
func (req *RecvReq) Timestamp() time.Time {
	return time.Unix(0, req.TimestampNs())
}

// PortNum returns packet's origin port number.
func (req *RecvReq) PortNum() int {
	return int(req.portnum)
}

// HwHash() returns hash calculated by the NIC.
func (req *RecvReq) HwHash() uint32 {
	return uint32(req.hw_hash)
}

// Handle encapsulates a device handle. It also contains
// all rings allocated through this handle, controls their
// abnormal closing.
type Handle struct {
	dev   C.snf_handle_t
	rings map[*Ring]*int32
	mtx   sync.Mutex
	wg    sync.WaitGroup
	sigCh chan os.Signal

	// 0   handle is operational
	// 1   handle is non-operational
	//     and can only be closed
	// 2   handle is closed
	state int32
}

func makeHandle(dev C.snf_handle_t) *Handle {
	return &Handle{
		dev:   dev,
		rings: make(map[*Ring]*int32),
		sigCh: make(chan os.Signal, 10)}
}

// states of an object
const (
	stateOk int32 = iota
	stateNotOk
	stateClosed
)

// Ring handle.
type Ring struct {
	ring C.snf_ring_t
	h    *Handle

	// 0   ring is operational
	// 1   ring is non-operational
	//     and can only be closed
	// 2   ring is closed
	state int32
}

func makeRing(ring C.snf_ring_t, h *Handle) *Ring {
	return &Ring{ring, h, 0}
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

// Receive timeout to control how the function blocks for the
// next packet.
func dur2ms(d time.Duration) C.int {
	// If the value is less than 0, the function can block indefinitely.
	if d < 0 {
		return -1
	}
	// if timeout is greater than 0, the caller indicates
	// a desired wait time in milliseconds. With a non-zero wait
	// time, the function only blocks if there are no outstanding
	// packets.
	if ms := int(d.Nanoseconds() / 1000000); ms > 0 {
		return C.int(ms)
	}

	// "If the value is 0, the function is guaranteed to never
	// enter a blocking state and returns EAGAIN unless there is a packet
	// waiting."
	// Author commentary: During heavy workload, timeout 0 may cause
	// other applications working on the same port to experience EINVAL
	// error. So timeout 0 will be reset to 1ms.
	return 1
}

// Init initializes the sniffer library.
func Init() error {
	return retErr(C.snf_init(C.SNF_VERSION_API))
}

func cvtIfAddrs(ifa *C.struct_snf_ifaddrs) *IfAddrs {
	return &IfAddrs{
		Name:      C.GoString(ifa.snf_ifa_name),
		PortNum:   uint32(ifa.snf_ifa_portnum),
		MaxRings:  int(ifa.snf_ifa_maxrings),
		MACAddr:   *(*[6]byte)(unsafe.Pointer(&ifa.snf_ifa_macaddr[0])),
		MaxInject: int(ifa.snf_ifa_maxinject),
		LinkState: int(ifa.snf_ifa_link_state),
		LinkSpeed: uint64(ifa.snf_ifa_link_speed),
	}
}

// GetIfAddrs gets a list of Sniffer-capable ethernet devices.
func GetIfAddrs() (res []IfAddrs, err error) {
	var p *C.struct_snf_ifaddrs
	if err = retErr(C.snf_getifaddrs(&p)); err == nil {
		defer C.snf_freeifaddrs(p)
		for ; p != nil; p = p.snf_ifa_next {
			res = append(res, *cvtIfAddrs(p))
		}
	}
	return
}

func getIfAddr(isfit func(*C.struct_snf_ifaddrs) bool) (ifa *IfAddrs, err error) {
	var p *C.struct_snf_ifaddrs
	if err = retErr(C.snf_getifaddrs(&p)); err == nil {
		defer C.snf_freeifaddrs(p)
		for ; p != nil; p = p.snf_ifa_next {
			if isfit(p) {
				return cvtIfAddrs(p), nil
			}
		}
		err = syscall.Errno(syscall.ENODEV)
	}
	return
}

// GetIfAddrByHW gets a Sniffer-capable ethernet devices with matching
// MAC address.
func GetIfAddrByHW(addr net.HardwareAddr) (*IfAddrs, error) {
	return getIfAddr(func(ifa *C.struct_snf_ifaddrs) bool {
		mac := *(*[6]byte)(unsafe.Pointer(&ifa.snf_ifa_macaddr[0]))
		return bytes.Equal(addr, mac[:])
	})
}

// GetIfAddrByName returns a Sniffer-capable ethernet devices with matching
// name.
func GetIfAddrByName(name string) (*IfAddrs, error) {
	return getIfAddr(func(ifa *C.struct_snf_ifaddrs) bool {
		return C.GoString(ifa.snf_ifa_name) == name
	})
}

// PortMask returns a mask of all Sniffer-capable ports that
// have their link state set to UP and a mask
// of all Sniffer-capable ports.
// The least significant bit represents port 0.
//
// ENODEV is returned in case of an error
// obtaining port information.
func PortMask() (linkup, valid uint32, err error) {
	var p *C.struct_snf_ifaddrs
	if err = retErr(C.snf_getifaddrs(&p)); err == nil {
		defer C.snf_freeifaddrs(p)
		for ; p != nil; p = p.snf_ifa_next {
			ifa := cvtIfAddrs(p)
			bit := uint32(1) << ifa.PortNum
			valid |= bit
			if ifa.LinkState == LinkUp {
				linkup |= bit
			}
		}
	}
	return
}

// OpenHandleDefaults opens a port for sniffing and allocates a device
// handle using system defaults. Single and multi-ring operation is possible.
//
// This function is a simplified version of OpenHandle() and ensures that
// the resulting device is opened according to system defaults.  Since
// the number of rings and flags can be set by module parameters, some
// installations may prefer to control device-level parameters in a
// system-wide configuration and keep the library calls simple.
//
// According to SNF documentation this call would be equivalent to
// OpenHandle(portnum, 0, 0, -1, 0)
// although it's not clear how '-1' flags would be interpreted.
// Also, this call is equivalent to OpenHandleWithOpts(portnum).
//
// portnum  Ports are numbered from 0 to N-1 where 'N' is the
// number of Myricom ports available on the system.
// GetIfAddrs() may be a useful utility to retrieve
// the port number by interface name or mac address if
// there are multiple.
//
// See OpenHandleWithOpts() for additional information.
func OpenHandleDefaults(portnum uint32) (*Handle, error) {
	return OpenHandleWithOpts(portnum)
}

// OpenHandleWithOpts opens a port for sniffing and allocates a device
// handle with specified options. See documentation for various
// options to see their applicability.
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
func OpenHandleWithOpts(portnum uint32, options ...HandlerOption) (*Handle, error) {
	var h *Handle
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

	err := retErr(C.snf_open(C.uint(portnum), opts.numRings, opts.rss,
		opts.dataRingSize, opts.flags, &dev))
	if err == nil {
		h = makeHandle(dev)
		defer h.houseKeep()
	}
	return h, err
}

// OpenHandle opens a port for sniffing and allocates a device handle. This
// function is mostly deprecated and use of OpenHandleWithOpts is strongly
// encouraged.
//
// portnum can be interpreted as an integer for a specific port number
// or as a mask when AggregatePortMask is specified in flags option.
// Port information can be obtained through GetIfAddrs() and
// active/valid masks are available with PortMask() method. As a
// special case, if portnum -1 is passed, the library will internally
// open a portmask as in valid mask returned in PortMask().
//
// num_rings Number of rings to allocate for receive-side scaling
// feature, which determines how many different threads can open their
// own ring via OpenRing().  If set to 0 or less than zero, default
// value is used unless SNF_NUM_RINGS is set in the environment.
//
// rss_flags is RSS flags to use by receive side scaling.
//
// dataring_sz represents the total amount of memory to be used to
// store incoming packet data for *all* rings to be opened.  If the
// value is set to 0 or less than 0, the library tries to choose a
// sensible default unless SNF_DATARING_SIZE is set in the
// environment.  The value can be specified in megabytes (if it is
// less than 1048576) or is otherwise considered to be in bytes.  In
// either case, the library may slightly adjust the user's request to
// satisfy alignment requirements (typically 2MB boundaries).
//
// flags is a mask of flags documented in SNF API Reference.
//
// Return values:
//
// 0 is successful. the port is opened and a value devhandle is
// allocated (see remarks).
//
// EBUSY: Device is already opened
//
// EINVAL: Invalid argument passed, most probably num_rings (if not,
// check syslog).
//
// E2BIG: Driver could not allocate requested dataring_sz (check
// syslog).
//
// ENOMEM: Either library or driver did not have enough memory to
// allocate handle descriptors (but not data ring).
//
// ENODEV: Device portnum can't be opened.
//
// If successful, the NIC switches from Ethernet mode to Capture mode
// and the Ethernet driver stops receiving packets.
//
// If successful, a call to Start() is required to the Sniffer-mode
// NIC to deliver packets to the host, and this call must occur after
// at least one ring is opened (OpenRing() method).
//
// Deprecated: Handles should be opened with OpenHandleWithOpts().
func OpenHandle(portnum uint32, numRings, rssFlags, flags int, dataringSz int64) (*Handle, error) {
	return OpenHandleWithOpts(portnum,
		HandlerOptFlags(flags),
		HandlerOptNumRings(numRings),
		HandlerOptRssFlags(rssFlags),
		HandlerOptDataRingSize(dataringSz))
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
		opts.rss = &C.struct_snf_rss_params{}
		C.set_rss_flags(opts.rss, C.int(flags))
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
func HandlerOptRssFunc(fn, ctx unsafe.Pointer) HandlerOption {
	return HandlerOption{func(opts *handlerOpts) {
		opts.rss = &C.struct_snf_rss_params{}
		C.set_rss_func(opts.rss, fn, ctx)
	}}
}

// LinkState gets link status on opened handle.
//
// Returns one of LinkDown or LinkUp.
//
// The cost of retrieving the link state requires a function call
// that reads state kept in kernel host memory (i.e. no PCI bus
// reads).
func (h *Handle) LinkState() (int, error) {
	var res uint32
	err := retErr(C.snf_get_link_state(h.dev, &res))
	return int(res), err
}

// LinkSpeed gets link speed on opened handle.
//
// Returns speed in bits-per-second for the link.
//
// The cost of retrieving the link state requires a function call
// that reads state kept in kernel host memory (i.e. no PCI bus
// reads).
func (h *Handle) LinkSpeed() (uint64, error) {
	var res C.ulong
	err := retErr(C.snf_get_link_speed(h.dev, &res))
	return uint64(res), err
}

// Start packet capture on a port.  Packet capture is only started if
// it is currently stopped or has not yet started for the first time.
//
// It is safe to restart packet capture via Start() and Stop()
// methods.  This call must be called before any packet can be
// received.
func (h *Handle) Start() error {
	return retErr(C.snf_start(h.dev))
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
	return retErr(C.snf_stop(h.dev))
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
	h.mtx.Lock()
	defer h.mtx.Unlock()
	err = retErr(C.snf_close(h.dev))
	if err == nil {
		// mark as closed
		signal.Stop(h.sigCh)
		close(h.sigCh)
	}

	// if EBUSY, you should close other rings
	return
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
	h.mtx.Lock()
	defer h.mtx.Unlock()
	var r C.snf_ring_t
	if err = retErr(C.snf_ring_open_id(h.dev, C.int(id), &r)); err == nil {
		ring = makeRing(r, h)
		h.rings[ring] = &ring.state
	}
	return
}

// Rings returns a list of all rings opened through this handle.
func (h *Handle) Rings() (r []*Ring) {
	h.mtx.Lock()
	defer h.mtx.Unlock()
	for ring := range h.rings {
		r = append(r, ring)
	}
	return
}

func (h *Handle) houseKeep() {
	wg := &h.wg

	wg.Add(1)
	go func() {
		// notify that this Handle is down
		// as soon as we're out of here
		defer wg.Done()
		for sig := range h.sigCh {
			h.mtx.Lock()
			// signal arrived
			fmt.Printf("SNF handle caught %v\n", sig)
			for _, state := range h.rings {
				atomic.StoreInt32(state, stateNotOk)
			}
			atomic.StoreInt32(&h.state, stateNotOk)
			h.mtx.Unlock()
		}
		// channel closes when Close() is called
		atomic.StoreInt32(&h.state, stateClosed)
	}()
}

// Wait until the Handle is successfully Close()-d.
func (h *Handle) Wait() {
	wg := &h.wg
	defer wg.Wait()
}

// SigChannel returns a channel for signal notifications.
// signal.Notify() may then be used on this channel.
//
// Signal is handled by raising the flag in all subsidiary rings.  All
// consequent receiving operations on those rings and the handle will
// return io.EOF error. As a rule of thumb that means that you should
// Close() those rings and the handle.
func (h *Handle) SigChannel() chan<- os.Signal {
	return h.sigCh
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
//
// If a ring is closed, all receive operations with that ring will
// return io.EOF error.
func (r *Ring) Close() error {
	h := r.h
	h.mtx.Lock()
	defer h.mtx.Unlock()
	if state, ok := h.rings[r]; ok {
		defer delete(h.rings, r)
		defer atomic.StoreInt32(state, stateClosed)
		return retErr(C.snf_ring_close(r.ring))
	}
	return nil
}

// TimeSourceState returns timesource information from opened handle
//
// Returns one of Timesource state constants.
//
// The cost of retrieving the timesource state requires a function
// call that reads state kept in kernel host memory (i.e. no PCI bus
// reads).
func (h *Handle) TimeSourceState() (int, error) {
	var res uint32
	err := retErr(C.snf_get_timesource_state(h.dev, &res))
	return int(res), err
}

// SetAppID sets the application ID.
//
// The user may set the application ID after the call to Init(), but
// before opening handle.  When the application ID is set, Sniffer
// duplicates receive packets to multiple applications.  Each
// application must have a unique ID.  Then, each application may
// utilize a different number of rings.  The application can be a
// process with multiple rings and threads.  In this case all rings
// have the same ID.  Or, multiple processes may share the same
// application ID.
//
// The user may store the application ID in the environment variable
// SNF_APP_ID, instead of calling this function.  Both actions have
// the same effect.  SNF_APP_ID overrides the ID set via SetAppID().
//
// The user may not run a mix of processes with valid application IDs
// (not -1) and processes with no IDs (-1).  Either all processes have
// valid IDs or none of them do.
//
// id is a 32-bit signed integer representing the application ID.  A
// valid ID is any value except -1. -1 is reserved and represents "no
// ID".
//
// EINVAL is returned if Init() has not been called or id is -1.
func SetAppID(id int32) error {
	return retErr(C.snf_set_app_id(C.int(id)))
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
	return stats, retErr(C.snf_ring_getstats(r.ring,
		(*C.struct_snf_ring_stats)(unsafe.Pointer(stats))))
}

// PortInfo returns information for the ring.
// For aggregated rings, returns information for each of the physical
// rings.
func (r *Ring) PortInfo() ([]*RingPortInfo, error) {
	var count C.int
	if err := retErr(C.snf_ring_portinfo_count(r.ring, &count)); err != nil {
		return nil, err
	}

	res := make([]*RingPortInfo, count)
	pi := make([]C.struct_snf_ring_portinfo, count)

	if err := retErr(C.snf_ring_portinfo(r.ring, &pi[0])); err != nil {
		return nil, err
	}
	for i, rc := range pi {
		res[i] = &RingPortInfo{
			Ring:     unsafe.Pointer(rc.ring),
			QSize:    uintptr(rc.q_size),
			PortCnt:  uint32(rc.portcnt),
			Portmask: uint32(rc.portmask),
			Data:     array2Slice(uintptr(rc.data_addr), int(rc.data_size)),
		}
	}
	return res, nil
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
// Return values: 0 is a successful packet delivery, recv_req is
// updated with packet information.  EINTR means the call was
// interrupted by a signal handler.  EAGAIN means that no packets are
// available (only when timeout is >= 0).
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
	return retErr(C.snf_ring_recv(r.ring, dur2ms(timeout), (*C.struct_snf_recv_req)(req)))
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
	out := C.recv_many(r.ring, dur2ms(timeout), (*C.struct_snf_recv_req)(&reqs[0]),
		C.int(len(reqs)), qi)
	return int(out.nreq_out), retErr(out.rc)
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
	return retErr(C.snf_ring_return_many(r.ring, datalen, qi))
}

// IsStateOk returns false if a Handle for the ring was notified with
// a signal, otherwise true.
func (r *Ring) IsStateOk() bool {
	return atomic.LoadInt32(&r.state) == stateOk
}

// IsStateOk returns false if a Handle was notified with a signal,
// otherwise true.
func (h *Handle) IsStateOk() bool {
	return atomic.LoadInt32(&h.state) == stateOk
}
