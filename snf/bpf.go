// Copyright 2019 Yerden Zhumabekov. All rights reserved.
//
// Use of this source code is governed by MIT license which
// can be found in the LICENSE file in the root of the source
// tree.
package snf

import (
	"errors"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/net/bpf"
)

type NetBPF struct {
	internal *bpf.VM
}

var _ RawFilter = (*NetBPF)(nil)
var _ Filter = (*pcap.BPF)(nil)

func (nf *NetBPF) Matches(data []byte) bool {
	res, err := nf.internal.Run(data)

	if err != nil {
		return false
	}

	return res != 0
}

// Match packets using net/bpf's VM
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

// Match packets using gopacket/pcap's BPF
func NewPcapBPF(snaplen int, bpffilter string) (Filter, error) {
	return pcap.NewBPF(layers.LinkTypeEthernet, snaplen, bpffilter)
}
