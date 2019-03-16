// Copyright 2019 Yerden Zhumabekov. All rights reserved.
//
// Use of this source code is governed by MIT license which
// can be found in the LICENSE file in the root of the source
// tree.

/*
Package snf is a wrapper for SNF library to support direct interaction with
Myricom/CSPI boards.

The purpose of the package is to avoid using libpcap-wrapped SNF
functionality in favor of more flexible and full-featured SNF C binding.
Hence it diminishes (but not fully negates, see below) dependency on
libpcap library.

In order to be able to use google/gopacket (layers etc.) functionality,
some interfaces in those packages are satisfied. Any feature requests
regarding extension of such integration are welcomed.

Most part of the package is a pretty much straightforward SNF API
wrappers. On top of that, RingReceiver is provided which wraps bulk
packet operation. RingReceiver also satisfies gopacket.ZeroCopyPacketDataSource
in case you work with google/gopacket/pcap.

The package utilizes BPF virtual machine from libpcap. Since original
SNF API doesn't expose any filtering service RingReceiver object provides
SetBPF method to apply offline BPF filtering.

It is extremely important from the system point of view that all the rings
and handles are properly closed upon program exit. Thus, some work was
done to handle signals in this library with minimal intrusion. It is
programmer's choice of whether to use this package's signal handling or
devise a custom one.

Some examples are provided to show various use cases, features, limitations
and so on.
*/
package snf

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

// #cgo CFLAGS: -I/opt/snf/include
// #cgo LDFLAGS: -L/opt/snf/lib -lsnf -lpcap
// #include <snf.h>
import "C"

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
// ports  when the protocol is TCP or UDP or SCTP, for
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

const (
	// PShared flag states that device can be process-sharable.  This
	// allows multiple independent processes to share rings on the
	// capturing device.  This option can be used to design a custom
	// capture solution but is also used in libpcap when multiple rings are
	// requested.  In this scenario, each libpcap device sees a fraction of
	// the traffic if multiple rings are used unless the RxDuplicate option
	// is used, in which case each libpcap device sees the same incoming
	// packets.
	PShared = C.SNF_F_PSHARED
	// AggregatePortMask shows that device can be opened for port aggregation
	// (or merging).  When this flag is passed, the portnum parameter in
	// OpenHandle() is interpreted as a bitmask where each set bit position
	// represents a port number. The  Sniffer library will then attempt to
	// open every portnum with its bit set in order to merge the incoming data
	// to the user from multiple ports. Subsequent calls to OpenRing() return
	// a ring handle that internally opens a ring on all underlying ports.
	AggregatePortMask = C.SNF_F_AGGREGATE_PORTMASK
	// RxDuplicate shows that device can duplicate packets to multiple rings
	// as opposed to applying RSS in order to split incoming packets across
	// rings.  Users should be aware that with N rings opened, N times the link
	// bandwidth is necessary to process incoming packets without drops.  The
	// duplication happens in the host rather than the NIC, so while only up to
	// 10Gbits of traffic crosses the PCIe, N times that bandwidth is necessary
	// on the host.
	//
	// When duplication is enabled, RSS options are ignored since every packet
	// is delivered to every ring.
	RxDuplicate = C.SNF_F_RX_DUPLICATE
)

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
type RingQInfo struct {
	// Amount of data available not yet received (approximate)
	Avail uintptr
	// Amount of data currently borrowed (exact)
	Borrowed uintptr
	// Amount of free space still available (approximate)
	Free uintptr
}

// RecvReq is a descriptor of a packet received on a data ring.
type RecvReq struct {
	// Pointer to packet directly in data ring
	Pkt []byte
	// 64-bit timestamp in nanoseconds
	Timestamp int64
	// Which port number received the packet
	PortNum uint32
	// Length of packet, with alignment in receive queue
	DataLength uint32
	// Hash calculated by the NIC.
	HWHash uint32
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
func dur2ms(d time.Duration) int {
	// If the value is less than 0, the function can block indefinitely.
	if d < 0 {
		return -1
	}
	// if timeout is greater than 0, the caller indicates
	// a desired wait time in milliseconds. With a non-zero wait
	// time, the function only blocks if there are no outstanding
	// packets.
	if ms := int(d.Nanoseconds() / 1000000); ms > 0 {
		return ms
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

// GetIfAddrs gets a list of Sniffer-capable ethernet devices.
func GetIfAddrs() ([]IfAddrs, error) {
	var res []IfAddrs

	var ifaAlloc *C.struct_snf_ifaddrs
	if err := retErr(C.snf_getifaddrs(&ifaAlloc)); err != nil {
		return nil, err
	}
	defer C.snf_freeifaddrs(ifaAlloc)

	for ifa := ifaAlloc; ifa != nil; ifa = ifa.snf_ifa_next {
		newifa := IfAddrs{
			Name:      C.GoString(ifa.snf_ifa_name),
			PortNum:   uint32(ifa.snf_ifa_portnum),
			MaxRings:  int(ifa.snf_ifa_maxrings),
			MaxInject: int(ifa.snf_ifa_maxinject),
			LinkState: int(ifa.snf_ifa_link_state),
			LinkSpeed: uint64(ifa.snf_ifa_link_speed),
		}
		for i := range newifa.MACAddr {
			newifa.MACAddr[i] = byte(ifa.snf_ifa_macaddr[i])
		}
		res = append(res, newifa)
	}
	return res, nil
}

func getIfAddr(isfit func(*IfAddrs) bool) (*IfAddrs, error) {
	var ifa []IfAddrs
	ifa, err := GetIfAddrs()
	if err != nil {
		return nil, err
	}
	for i := range ifa {
		if isfit(&ifa[i]) {
			return &ifa[i], nil
		}
	}
	return nil, syscall.Errno(syscall.ENODEV)
}

// GetIfAddrByHW gets a Sniffer-capable ethernet devices with matching
// MAC address.
func GetIfAddrByHW(addr net.HardwareAddr) (*IfAddrs, error) {
	return getIfAddr(func(x *IfAddrs) bool {
		return bytes.Equal(addr, x.MACAddr[:])
	})
}

// GetIfAddrByName returns a Sniffer-capable ethernet devices with matching
// name.
func GetIfAddrByName(name string) (*IfAddrs, error) {
	return getIfAddr(func(x *IfAddrs) bool {
		return x.Name == name
	})
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
//
// portnum  Ports are numbered from 0 to N-1 where 'N' is the
// number of Myricom ports available on the system.
// GetIfAddrs() may be a useful utility to retrieve
// the port number by interface name or mac address if
// there are multiple.
//
// See OpenHandle() for additional information.
func OpenHandleDefaults(portnum uint32) (*Handle, error) {
	rssFlags := RssIP | RssSrcPort | RssDstPort
	return OpenHandle(portnum, 0, rssFlags, -1, 0)
}

// OpenHandle opens a port for sniffing and allocates a device handle.
//
// portnum Port numbers can be interpreted as integers for a
// specific port number or as a mask when
// AggregatePortMask is specified in flags.  Port
// information can be obtained through GetIfAddrs()
// and active/valid masks are available with
// PortMask() method. As a special case, if
// portnum -1 is passed, the library will internally open
// a portmask as in valid mask returned in PortMask().
//
// num_rings Number of rings to allocate for receive-side scaling
// feature, which determines how many different threads
// can open their own ring via OpenRing().  If set
// to 0 or less than zero, default value is used unless
// SNF_NUM_RINGS is set in the environment.
//
// rss_flags is RSS flags to use by receive side scaling.
//
// dataring_sz represents the total amount of memory to be used to
// store incoming packet data for *all* rings to be
// opened.  If the value is set to 0 or less than 0,
// the library tries to choose a sensible default
// unless SNF_DATARING_SIZE is set in the environment.
// The value can be specified in megabytes (if it is
// less than 1048576) or is otherwise considered to be
// in bytes.  In either case, the library may slightly
// adjust the user's request to satisfy alignment
// requirements (typically 2MB boundaries).
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
// EINVAL: Invalid argument passed, most probably num_rings (if
// not, check syslog).
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
// If successful, a call to Start() is required to the
// Sniffer-mode NIC to deliver packets to the host, and this call
// must occur after at least one ring is opened (OpenRing() method).
func OpenHandle(portnum uint32, numRings, rssFlags, flags int, dataringSz int64) (*Handle, error) {
	var h *Handle
	var dev C.snf_handle_t
	var rss C.struct_snf_rss_params
	rss.mode = C.SNF_RSS_FLAGS
	// workaround C 'union'
	*(*int)(unsafe.Pointer(&rss.params[0])) = rssFlags
	err := retErr(C.snf_open(C.uint(portnum), C.int(numRings), &rss, C.long(dataringSz), C.int(flags), &dev))
	if err == nil {
		h = makeHandle(dev)
		defer h.houseKeep()
	}
	return h, err
}

// LinkState gets link status on opened handle.
//
// Returns one of LinkDown or LinkUp.
//
// The cost of retrieving the link state requires a function call
// that reads state kept in kernel host memory (i.e. no PCI bus
// reads).
func (h *Handle) LinkState() (int, error) {
	if atomic.LoadInt32(&h.state) != stateOk {
		return 0, io.EOF
	}
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
	if atomic.LoadInt32(&h.state) != stateOk {
		return 0, io.EOF
	}
	var res C.ulong
	err := retErr(C.snf_get_link_speed(h.dev, &res))
	return uint64(res), err
}

//
// Start packet capture on a port.  Packet capture is only started if it
// is currently stopped or has not yet started for the first time.
//
// It is safe to restart packet capture via Start() and Stop() methods.
// This call must be called before any packet can be received.
func (h *Handle) Start() error {
	if atomic.LoadInt32(&h.state) != stateOk {
		return io.EOF
	}
	return retErr(C.snf_start(h.dev))
}

// Stop packet capture on a port.  This function should be used carefully
// in multi-process mode as a single stop command stops packet capture on
// all rings.  It is usually best to simply Close() a ring to
// stop capture on a ring.
//
// Stop instructs the NIC to drop all packets until the next
// Start() or until the port is closed.  The NIC only resumes
// delivering packets when the port is closed, not when traffic is
// stopped.
func (h *Handle) Stop() error {
	if atomic.LoadInt32(&h.state) != stateOk {
		return io.EOF
	}
	return retErr(C.snf_stop(h.dev))
}

// Close port.
//
// This function can be closed once all opened rings (if any) are closed
// through ring's Close() method.  Once a port is determined to be
// closable, it is implicitly called as if a call had been previously made
// to Stop() method.
//
// EBUSY is returned if some rings are still opened and the port cannot be
// closed (yet).
//
// If successful, all resources allocated at open time are
// unallocated and the device switches from Sniffer mode to Ethernet mode
// such that the Ethernet driver resumes receiving packets.
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
// Please be sure that you close the ring once you've done
// working on it. Leaking rings may lead to packet drops in
// neighbour applications working on the same NIC.
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
// ring_id Ring number to open, from 0 to num_rings - 1.  If
// the value is -1, this function behaves as if OpenRing()
// was called.
//
// Ring handle allocated if the call is successful.
//
// EBUSY is returned if id == -1, Too many rings already opened.
// if id >= 0, that ring is already opened.
//
// Unlike OpenRing(), this function ignores the environment
// variable SNF_RING_ID since the expectation is that users want to
// directly control ring allocation (unlike through libpcap).
//
// Please be sure that you close the ring once you've done
// working on it. Leaking rings may lead to packet drops in
// neighbour applications working on the same NIC.
//
// If successful, a call to Handle's Start() is required to the
// Sniffer-mode NIC to deliver packets to the host.
func (h *Handle) OpenRingID(id int) (ring *Ring, err error) {
	if atomic.LoadInt32(&h.state) != stateOk {
		return nil, io.EOF
	}
	h.mtx.Lock()
	defer h.mtx.Unlock()
	var r C.snf_ring_t
	if err = retErr(C.snf_ring_open_id(h.dev, C.int(id), &r)); err == nil {
		ring = makeRing(r, h)
		h.rings[ring] = &ring.state
	}
	return
}

// Rings returns a list of all rings opened through
// this handle.
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
			// signal arrived
			fmt.Printf("SNF handle caught %v\n", sig)
			for _, state := range h.rings {
				atomic.StoreInt32(state, stateNotOk)
			}
			atomic.StoreInt32(&h.state, stateNotOk)
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

// SigChannel returns a channel for signal notifications. signal.Notify()
// may then be used on this channel.
//
// Signal is handled by raising the flag in all subsidiary rings.
// All consequent receiving operations on those rings and the handle
// will return io.EOF error. As a rule of thumb that means that you
// should Close() those rings and the handle.
func (h *Handle) SigChannel() chan<- os.Signal {
	return h.sigCh
}

// Close a ring
//
// This function is used to inform the underlying device that no further
// calls to Recv() will be made.  If the device is not
// subsequently closed (Handle's Close()), all packets that would have been
// delivered to this ring are dropped.  Also, by calling this function,
// users confirm that all packet processing for packets obtained on this
// ring via ring's Recv() is complete.
//
// Returns 0 (successful).
//
// The user has processed the last packet obtained with
// Recv() and such and the device can safely be closed via
// Handle's Close() if all other rings are also closed.
// All packet data memory returned by Ring or RingReceiver
// is reclaimed by SNF API and cannot be dereferenced.
//
// If a ring is closed, all receive operations with that ring
// will return io.EOF error.
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
// The cost of retrieving the timesource state requires a
// function call that reads state kept in kernel host memory
// (i.e. no PCI bus reads).
func (h *Handle) TimeSourceState() (int, error) {
	if atomic.LoadInt32(&h.state) != stateOk {
		return 0, io.EOF
	}
	var res uint32
	err := retErr(C.snf_get_timesource_state(h.dev, &res))
	return int(res), err
}

// PortMask returns a mask of all Sniffer-capable ports that
// have their link state set to UP and a mask
// of all Sniffer-capable ports.
// The least significant bit represents port 0.
//
// ENODEV is returned in case of an error
// obtaining port information.
func PortMask() (linkup, valid uint32, err error) {
	var ifa []IfAddrs
	ifa, err = GetIfAddrs()
	if err == nil {
		for _, ifaddr := range ifa {
			bit := uint32(1) << ifaddr.PortNum
			valid |= bit
			if ifaddr.LinkState == LinkUp {
				linkup |= bit
			}
		}
	}
	return
}

// SetAppID sets the application ID.
//
// The user may set the application ID after the call to Init(), but
// before OpenHandle().  When the application ID is set, Sniffer duplicates
// receive packets to multiple applications.  Each application must have
// a unique ID.  Then, each application may utilize a different number of
// rings.  The application can be a process with multiple rings and threads.
// In this case all rings have the same ID.  Or, multiple processes may share
// the same application ID.
//
// The user may store the application ID in the environment variable
// SNF_APP_ID, instead of calling this function.  Both actions have the same
// effect.  SNF_APP_ID overrides the ID set via SetAppID().
//
// The user may not run a mix of processes with valid application IDs (not -1)
// and processes with no IDs (-1).  Either all processes have valid IDs or
// none of them do.
//
// id is a 32-bit signed integer representing the application ID.
// A valid ID is any value except -1. -1 is reserved and represents
// "no ID".
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
	if atomic.LoadInt32(&r.state) != stateOk {
		return nil, io.EOF
	}
	stats := &RingStats{}
	return stats, retErr(C.snf_ring_getstats(r.ring,
		(*C.struct_snf_ring_stats)(unsafe.Pointer(stats))))
}

// PortInfo returns information for the ring.
// For aggregated rings, returns information for each of the physical
// rings.
func (r *Ring) PortInfo() ([]*RingPortInfo, error) {
	if atomic.LoadInt32(&r.state) != stateOk {
		return nil, io.EOF
	}
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
// This function is used to return the next available packet in a receive
// ring.  The function can block indefinitely, for a specific timeout or
// be used as a non-blocking call with a timeout of 0.
//
// timeout is a receive timeout to control how the function blocks
// for the next packet. If the value is less than 0, the function can
// block indefinitely.  If the value is 0, the function is guaranteed to
// never enter a blocking state and returns EAGAIN unless there is a
// packet waiting.  If the value is greater than 0, the caller indicates
// a desired wait time in milliseconds.  With a non-zero wait time, the
// function only blocks if there are no outstanding packets.  If the
// timeout expires before a packet can be received, the function returns
// EAGAIN (and not ETIMEDOUT).  In all cases, users should expect that
// the function may return EINTR as the result of signal delivery.
//
// req is a Receive Packet structure, only updated when the function
// returns 0 for a successful packet receive (RecvReq).
//
// Return values:
// 0 is a successful packet delivery, recv_req is updated with packet
// information.
// EINTR means the call was interrupted by a signal handler.
// EAGAIN means that no packets are available (only when timeout is >= 0).
//
// The returned packet always points directly into the receive
// ring where the NIC has DMAed the packet (there are no copies).  As
// such, the user obtains a pointer to library/driver allocated memory.
// Users can modify the contents of the packets but should remain within
// the slice boundaries.
//
// Upon calling the function, the library assumes that the user
// is done processing the previous packet.  The same assumption is made
// when the ring is closed (ring's Close() method).
func (r *Ring) Recv(timeout time.Duration, req *RecvReq) error {
	if atomic.LoadInt32(&r.state) != stateOk {
		return io.EOF
	}
	ms := dur2ms(timeout)
	var rc C.struct_snf_recv_req
	err := retErr(C.snf_ring_recv(r.ring, C.int(ms), &rc))
	if err == nil {
		convert(req, &rc)
	}
	return err
}

func convert(req *RecvReq, rc *C.struct_snf_recv_req) {
	req.Pkt = getData(rc)
	req.Timestamp = int64(rc.timestamp)
	req.PortNum = uint32(rc.portnum)
	req.DataLength = uint32(rc.length_data)
	req.HWHash = uint32(rc.hw_hash)
}

func getData(rc *C.struct_snf_recv_req) []byte {
	return array2Slice(uintptr(rc.pkt_addr), int(rc.length))
}
