// Copyright 2019 Yerden Zhumabekov. All rights reserved.
//
// Use of this source code is governed by MIT license which
// can be found in the LICENSE file in the root of the source
// tree.

package snf

import (
	"errors"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/net/bpf"
)

/*
#include <stdlib.h>
#include <pcap.h>
#include <filter.h>
*/
import "C"

// NetBPF is an instance of a BPF virtual machine
// implemented in golang.org/x/net/bpf package.
type NetBPF struct {
	internal *bpf.VM
}

var _ RawFilter = (*NetBPF)(nil)
var _ Filter = (*pcap.BPF)(nil)

// Matches return true if packet matches the filter condition.
func (nf *NetBPF) Matches(data []byte) bool {
	res, err := nf.internal.Run(data)

	if err != nil {
		return false
	}

	return res != 0
}

// NewNetBPF returns filter which matches packets using net/bpf's VM.
func NewNetBPF(snaplen int, bpffilter string) (RawFilter, error) {
	pcapInstructions, _ := pcap.CompileBPFFilter(layers.LinkTypeEthernet, snaplen, bpffilter)
	rawInstructions := make([]bpf.RawInstruction, len(pcapInstructions))

	for i, pcapIns := range pcapInstructions {
		rawInstructions[i].Op = pcapIns.Code
		rawInstructions[i].Jt = pcapIns.Jt
		rawInstructions[i].Jf = pcapIns.Jf
		rawInstructions[i].K = pcapIns.K
	}

	instructions, allParsed := bpf.Disassemble(rawInstructions)
	if !allParsed {
		return nil, errors.New("could not translate all pcap bpf instructions")
	}

	vm, err := bpf.NewVM(instructions)
	if err != nil {
		return nil, err
	}

	return &NetBPF{internal: vm}, nil
}

// NewPcapBPF returns filter which matches packets using gopacket/pcap's BPF.
func NewPcapBPF(snaplen int, bpffilter string) (Filter, error) {
	return pcap.NewBPF(layers.LinkTypeEthernet, snaplen, bpffilter)
}

// SetBPF sets Berkeley Packet Filter on a ring.
//
// Like SetFilter this function allows to set a BPF on a ring.
// The installed BPF will be matched across every packet
// received on it with Ring.Recv or RingReceiver.RawNext.
//
// Unlike SetFilter, BPF check is performed in the very same
// receiving Cgo call and, because of that, is more efficient.
//
// If the packet don't match BPF, Recv() will return
// ENOMSG error instead of packet. RingReceiver.RawNext()
// will silently skip this packet.
//
// SetBPF will silently replace previously set filter.
// You can call this function at any point in your program
// but make sure that there is no concurrent packet reading
// activity on the ring at the moment.
func (r *Ring) SetBPF(snaplen int, expr string) error {
	insns, err := pcap.CompileBPFFilter(layers.LinkTypeEthernet, snaplen, expr)
	if err != nil {
		return err
	}

	return r.SetBPFInstruction(insns)
}

func bpfMake(insns []pcap.BPFInstruction, fp *C.struct_bpf_program) error {
	c_insns := make([]C.struct_bpf_insn, len(insns))
	for i, _ := range c_insns {
		c_insns[i].code = C.u_short(insns[i].Code)
		c_insns[i].jf = C.u_char(insns[i].Jf)
		c_insns[i].jt = C.u_char(insns[i].Jt)
		c_insns[i].k = C.uint(insns[i].K)
	}

	return retErr(C.go_bpf_make(C.int(len(c_insns)), &c_insns[0], fp))
}

// SetBPFInstruction sets Berkeley Packet Filter on a ring.
// The BPF is represented as an array of instructions.
//
// See SetBPF on notes and caveats.
func (r *Ring) SetBPFInstruction(insns []pcap.BPFInstruction) error {
	var fp C.struct_bpf_program
	if err := bpfMake(insns, &fp); err != nil {
		return err
	}
	r.fp = fp
	return nil
}

// pcapFilterTest filters given packet through filter "repeat" times.
func pcapFilterTest(ci gopacket.CaptureInfo, pkt []byte, snaplen int, expr string, repeat int) (int, error) {
	insns, err := pcap.CompileBPFFilter(layers.LinkTypeEthernet, snaplen, expr)
	if err != nil {
		return 0, err
	}

	var fp C.struct_bpf_program
	if err := bpfMake(insns, &fp); err != nil {
		return 0, err
	}
	defer C.pcap_freecode(&fp)

	var hdr C.struct_pcap_pkthdr
	hdr.ts.tv_sec = C.long(ci.Timestamp.Unix())
	hdr.ts.tv_usec = C.long(ci.Timestamp.Nanosecond() / 1000)
	hdr.caplen = C.uint(len(pkt))
	hdr.len = hdr.caplen

	return int(C.go_bpf_test(&fp, &hdr, (*C.u_char)(&pkt[0]), C.int(repeat))), nil
}
