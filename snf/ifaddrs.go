package snf

/*
#include "wrapper.h"
*/
import "C"

import (
	"bytes"
	"fmt"
	"net"
	"runtime"
	"unsafe"
)

// IfAddrs is a structure to map Interfaces to Sniffer port numbers.
// It can be copied by value.
type IfAddrs struct {
	head **C.struct_snf_ifaddrs
	ifa  *C.struct_snf_ifaddrs
}

// GetIfAddrs gets a list of Sniffer-capable ethernet devices.
func GetIfAddrs() ([]IfAddrs, error) {
	var res []IfAddrs
	head := new(*C.struct_snf_ifaddrs)
	err := retErr(C.snf_getifaddrs(head))
	if err == nil {
		runtime.SetFinalizer(head, func(head **C.struct_snf_ifaddrs) {
			C.snf_freeifaddrs(*head)
		})
		for p := *head; p != nil; p = p.snf_ifa_next {
			res = append(res, IfAddrs{head, p})
		}
	}
	return res, err
}

// String implements fmt.Stringer interface.
func (p *IfAddrs) String() string {
	return fmt.Sprintf("n=%d,name=%s,hwaddr=%v,maxRings=%d,maxInject=%d,linkState=%d,linkSpeed=%d",
		p.PortNum(), p.Name(), net.HardwareAddr(p.MACAddr()),
		p.MaxRings(), p.MaxInject(), p.LinkState(), p.LinkSpeed())
}

// Name returns interface name, as in ifconfig.
func (p *IfAddrs) Name() string {
	return C.GoString(p.ifa.snf_ifa_name)
}

// PortNum returns port's index in SNF library.
func (p *IfAddrs) PortNum() uint32 {
	return uint32(p.ifa.snf_ifa_portnum)
}

// MaxRings returns maximum RX rings supported by the port.
func (p *IfAddrs) MaxRings() int {
	return int(p.ifa.snf_ifa_maxrings)
}

// MACAddr returns MAC address of the port.
func (p *IfAddrs) MACAddr() []byte {
	x := *(*[6]byte)(unsafe.Pointer(&p.ifa.snf_ifa_macaddr[0]))
	return x[:]
}

// MaxInject returns maximum TX injection handles supported by the
// port.
func (p *IfAddrs) MaxInject() int {
	return int(p.ifa.snf_ifa_maxinject)
}

// LinkState returns underlying port's state (DOWN or UP).
func (p *IfAddrs) LinkState() int {
	return int(p.ifa.snf_ifa_link_state)
}

// LinkSpeed returns Link Speed in bps.
func (p *IfAddrs) LinkSpeed() uint64 {
	return uint64(p.ifa.snf_ifa_link_speed)
}

func lookupIfAddr(fn func(ifa *IfAddrs) bool) (*IfAddrs, error) {
	list, err := GetIfAddrs()
	if err == nil {
		for _, ifa := range list {
			if fn(&ifa) {
				return &ifa, nil
			}
		}
	}
	return nil, err
}

// GetIfAddrByHW gets a Sniffer-capable ethernet devices with matching
// MAC address.
//
// Found IfAddr struct is returned. If not found, (nil, nil) will be returned.
// If unable to retrieve interfaces from SNF, (nil, err) where err is
// correspoding error will be returned.
func GetIfAddrByHW(addr net.HardwareAddr) (*IfAddrs, error) {
	return lookupIfAddr(func(ifa *IfAddrs) bool { return bytes.Equal(addr, ifa.MACAddr()) })
}

// GetIfAddrByName returns a Sniffer-capable ethernet devices with matching
// name.
//
// Found IfAddr struct is returned. If not found, (nil, nil) will be returned.
// If unable to retrieve interfaces from SNF, (nil, err) where err is
// correspoding error will be returned.
func GetIfAddrByName(name string) (*IfAddrs, error) {
	return lookupIfAddr(func(ifa *IfAddrs) bool { return name == ifa.Name() })
}

// PortMask returns a mask of all Sniffer-capable ports that
// have their link state set to UP and a mask
// of all Sniffer-capable ports.
// The least significant bit represents port 0.
//
// ENODEV is returned in case of an error
// obtaining port information.
func PortMask() (linkup, valid uint32, err error) {
	list, err := GetIfAddrs()
	if err == nil {
		for _, ifa := range list {
			bit := uint32(1) << ifa.PortNum()
			if valid |= bit; ifa.LinkState() == LinkUp {
				linkup |= bit
			}
		}
	}
	return linkup, valid, err
}
