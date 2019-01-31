/*
This is a wrapper for SNF library to support direct interaction with
Myricom/CSPI boards.

The purpose of the package is to avoid using libpcap-wrapped SNF
functionality in favor of more flexible and full-featured SNF C binding.
Hence it diminishes (but not fully negates, see below) dependency on
libpcap library.

In order to be able to use google/gopacket (layers etc.) functionality,
some interfaces in those packages are satisfied. Any feature requests
regarding extension of such integration are welcomed.

Currently, the package does not provide explicit BPF functionality since
the BPF compiler is available in libpcap library only and such dependency
would be an overkill. Filter interface is provided in the package which
mimics the BPF behaviour in gopacket/pcap package.

Most part of the package is a pretty much straightforward SNF API
wrappers. On top of that, RingReceiver is provided which wraps bulk
packet operation. RingReceiver also satisfies gopacket.ZeroCopyPacketDataSource
in case you work with gopacket/pcap.
*/
package snf

import (
	"reflect"
	"time"
	"unsafe"
)

// #cgo CFLAGS: -I/opt/snf/include
// #cgo LDFLAGS: -L/opt/snf/lib -lsnf
// #include <snf.h>
// int getportmask(uint32_t *l, uint32_t *v) {
//   int x;
//   int res = snf_getportmask_linkup(l, &x);
//   if (res < 0) {
//     return res;
//   }
//   return snf_getportmask_valid(v, &x);
// }
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
	// Device can be process-sharable.  This allows multiple independent
	// processes to share rings on the capturing device.  This option can be
	// used to design a custom capture solution but is also used in libpcap
	// when multiple rings are requested.  In this scenario, each libpcap
	// device sees a fraction of the traffic if multiple rings are used unless
	// the RxDuplicate option is used, in which case each libpcap
	// device sees the same incoming packets.
	PShared = C.SNF_F_PSHARED
	// Device can be opened for port aggregation (or merging).  When this flag
	// is passed, the portnum parameter in OpenHandle() is interpreted as
	// a bitmask where each set bit position represents a port number.  The
	// Sniffer library will then attempt to open every portnum with its bit set
	// in order to merge the incoming data to the user from multiple ports.
	// Subsequent calls to OpenRing() return a ring handle that
	// internally opens a ring on all underlying ports.
	AggregatePortMask = C.SNF_F_AGGREGATE_PORTMASK
	// Device can duplicate packets to multiple rings as opposed to applying
	// RSS in order to split incoming packets across rings.  Users should be
	// aware that with N rings opened, N times the link bandwidth is necessary
	// to process incoming packets without drops.  The duplication happens in
	// the host rather than the NIC, so while only up to 10Gbits of traffic
	// crosses the PCIe, N times that bandwidth is necessary on the host.
	//
	// When duplication is enabled, RSS options are ignored since every packet
	// is delivered to every ring.
	RxDuplicate = C.SNF_F_RX_DUPLICATE
)

// Structure to map Interfaces to Sniffer port numbers
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

// Receive ring information
type RingPortInfo struct {
	// Single ring
	*Ring
	// Size of the data queue
	QSize uintptr
	// How many physical ports deliver to this receive ring
	PortCnt uint32
	// Which ports deliver to this receive ring
	Portmask uint32
	// Address of data ring
	DataAddr unsafe.Pointer
	// Size of the data ring
	DataSize uintptr
}

// Queue consumption information.
type RingQInfo struct {
	// Amount of data available not yet received (approximate)
	Avail uintptr
	// Amount of data currently borrowed (exact)
	Borrowed uintptr
	// Amount of free space still available (approximate)
	Free uintptr
}

// Structure to return statistics from an injection handle.  The
// hardware-specific counters (nic_) apply to all injection handles.
type InjectStats struct {
	// Number of packets sent by this injection endpoint
	InjPktSend uint64
	// Number of total packets sent by Hardware Interface
	NicPktSend uint64
	// Number of raw bytes sent by Hardware Interface (see nic_bytes_recv)
	NicBytesSend uint64
}

// Structure to describe a packet received on a data ring.
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

// Device handle.
type Handle struct {
	dev C.snf_handle_t
}

// Ring handle.
type Ring struct {
	ring C.snf_ring_t
}

// Structure to return statistics from a ring.  The Hardware-specific
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

// Initializes the sniffer library.
func Init() error {
	return retErr(C.snf_init(C.SNF_VERSION_API))
}

// Get a list of Sniffer-capable ethernet devices.
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
		for i, _ := range newifa.MACAddr {
			newifa.MACAddr[i] = byte(ifa.snf_ifa_macaddr[i])
		}
		res = append(res, newifa)
	}
	return res, nil
}

// Opens a port for sniffing and allocates a device handle using system
// defaults.
//
// Open device for single or multi-ring operation
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
	var dev C.snf_handle_t
	err := retErr(C.snf_open_defaults(C.uint(portnum), &dev))
	return &Handle{dev}, err
}

// Opens a port for sniffing and allocates a device handle.
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
	var dev C.snf_handle_t
	var rss C.struct_snf_rss_params
	rss.mode = C.SNF_RSS_FLAGS
	// workaround C 'union'
	*(*int)(unsafe.Pointer(&rss.params[0])) = rssFlags
	err := retErr(C.snf_open(C.uint(portnum), C.int(numRings), &rss, C.long(dataringSz), C.int(flags), &dev))
	return &Handle{dev}, err
}

// Get link status on opened handle
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

// Get link speed on opened handle
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

//
// Start packet capture on a port.  Packet capture is only started if it
// is currently stopped or has not yet started for the first time.
//
// It is safe to restart packet capture via Start() and Stop() methods.
// This call must be called before any packet can be received.
func (h *Handle) Start() error {
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
//
func (h *Handle) Stop() error {
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
func (h *Handle) Close() error {
	return retErr(C.snf_close(h.dev))
}

// Opens the next available ring
//
// Ring handle allocated if the call is successful.
//
// EBUSY is returned if too many rings already opened.
//
// This function will consider the value of the SNF_RING_ID
// environment variable.  For more control over ring allocation,
// consider using OpenRingId() method instead.
//
// If successful, a call to Start() method is required to the
// Sniffer-mode NIC to deliver packets to the host.
func (h *Handle) OpenRing() (*Ring, error) {
	var r C.snf_ring_t
	err := retErr(C.snf_ring_open(h.dev, &r))
	return &Ring{r}, err
}

// Opens a ring from an opened port.
//
// ring_id Ring number to open, from 0 to num_rings - 1.  If
// the value is -1, this function behaves as if
// ring's Open() was called.
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
// If successful, a call to Handle's Start() is required to the
// Sniffer-mode NIC to deliver packets to the host.
func (h *Handle) OpenRingId(id int) (*Ring, error) {
	var r C.snf_ring_t
	err := retErr(C.snf_ring_open_id(h.dev, C.int(id), &r))
	return &Ring{r}, err
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

func (r *Ring) Close() error {
	return retErr(C.snf_ring_close(r.ring))
}

// Get Timesource information from opened handle
//
// Returns one of Timesource state constants.
//
// The cost of retrieving the timesource state requires a
// function call that reads state kept in kernel host memory
// (i.e. no PCI bus reads).
func (h *Handle) TimeSourceState() (int, error) {
	var res uint32
	err := retErr(C.snf_get_timesource_state(h.dev, &res))
	return int(res), err
}

// Get a mask of all Sniffer-capable ports that
// have their link state set to UP and a mask
// of all Sniffer-capable ports.
// The least significant bit represents port 0.
//
// ENODEV is returned in case of an error
// obtaining port information.
func PortMask() (linkup, valid uint32, err error) {
	var l, v C.uint
	err = retErr(C.getportmask(&l, &v))
	return uint32(l), uint32(v), err
}

// Sets the application ID.
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
// effect.  SNF_APP_ID overrides the ID set via SetAppId().
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
func SetAppId(id int32) error {
	return retErr(C.snf_set_app_id(C.int(id)))
}

// Get statistics from a receive ring.
//
// This call is provided as a convenience and should not be
// relied on for time-critical applications or for high levels of
// accuracy.  Statistics are only updated by the NIC periodically.
//
// Administrative clearing of NIC counters while a Sniffer-based
// application is running may cause some of the counters to be incorrect.
func (r *Ring) Stats() (*RingStats, error) {
	var stats C.struct_snf_ring_stats
	err := retErr(C.snf_ring_getstats(r.ring, &stats))
	return &RingStats{
		NicPktRecv:      uint64(stats.nic_pkt_recv),
		NicPktOverflow:  uint64(stats.nic_pkt_overflow),
		NicPktBad:       uint64(stats.nic_pkt_bad),
		RingPktRecv:     uint64(stats.ring_pkt_recv),
		RingPktOverflow: uint64(stats.ring_pkt_overflow),
		NicBytesRecv:    uint64(stats.nic_bytes_recv),
		SnfPktOverflow:  uint64(stats.snf_pkt_overflow),
		NicPktDropped:   uint64(stats.nic_pkt_dropped),
	}, err
}

// Returns information for the ring.
// For aggregated rings, returns information for each of the physical
// rings.  It is up to the user to make sure they have allocated enough
// memory to hold the information for all the physical rings in an
// aggregated ring.
func (r *Ring) PortInfo() (*RingPortInfo, error) {
	var rc C.struct_snf_ring_portinfo
	err := retErr(C.snf_ring_portinfo(r.ring, &rc))
	return &RingPortInfo{
		Ring:     &Ring{rc.ring},
		QSize:    uintptr(rc.q_size),
		PortCnt:  uint32(rc.portcnt),
		Portmask: uint32(rc.portmask),
		DataAddr: unsafe.Pointer(uintptr(rc.data_addr)),
		DataSize: uintptr(rc.data_size),
	}, err
}

// Receive next packet from a receive ring.
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
// req is a Receive Packet structure, only updated when a the
// function returns 0 for a successful packet receive
// (RecvReq).
//
// Return values:
// 0 is a successful packet delivery, recv_req is updated with packet
// information.
// EINTR means the call was interrupted by a signal handler
// EAGAIN means that no packets available (only when timeout is >= 0).
//
// The packet returned always points directly into the receive
// ring where the NIC has DMAed the packet (there are no copies).  As
// such, the user obtains a pointer to library/driver allocated memory.
// Users can modify the contents of the packets but should remain within
// the slice boundaries.
//
// Upon calling the function, the library assumes that the user
// is done processing the previous packet.  The same assumption is made
// when the ring is closed (ring's Close() method).
func (r *Ring) Recv(timeout time.Duration, req *RecvReq) error {
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

func getData(rc *C.struct_snf_recv_req) (data []byte) {
	sh := (*reflect.SliceHeader)(unsafe.Pointer(&data))
	sh.Data = uintptr(unsafe.Pointer(rc.pkt_addr))
	sh.Len = int(rc.length)
	sh.Cap = sh.Len
	return
}
