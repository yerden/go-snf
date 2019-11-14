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
binding.

In order to be able to use google/gopacket (layers etc.)
functionality, some interfaces in those packages are satisfied. Any
feature requests regarding extension of such integration are welcomed.

Some examples are provided to show various use cases, features,
limitations and so on.
*/
package snf

/*
#cgo CFLAGS: -I/opt/snf/include
#cgo LDFLAGS: -L/opt/snf/lib -lsnf -lpcap
#include <snf.h>
#include "wrapper.h"
*/
import "C"

import (
	"reflect"
	"time"
	"unsafe"
)

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
	// rings are requested. In this scenario, each libpcap device sees
	// a fraction of the traffic if multiple rings are used unless the
	// RxDuplicate option is used, in which case each libpcap device
	// sees the same incoming packets.
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

// Timestamp() returns 64-bit timestamp in nanoseconds.
func (req *RecvReq) Timestamp() int64 {
	return int64(req.timestamp)
}

// PortNum returns packet's origin port number.
func (req *RecvReq) PortNum() int {
	return int(req.portnum)
}

// HwHash() returns hash calculated by the NIC.
func (req *RecvReq) HwHash() uint32 {
	return uint32(req.hw_hash)
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
// valid ID is any value except -1 which is reserved and represents
// "no ID".
//
// EINVAL is returned if Init() has not been called or id is -1.
func SetAppID(id int32) error {
	return retErr(C.snf_set_app_id(C.int(id)))
}
