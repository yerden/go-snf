// Copyright 2019 Yerden Zhumabekov. All rights reserved.
//
// Use of this source code is governed by MIT license which
// can be found in the LICENSE file in the root of the source
// tree.

package snf

/*
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include "filter.h"
*/
import "C"

import (
	"errors"
	"unsafe"

	"golang.org/x/net/bpf"
)

func makeProgram(insns []bpf.RawInstruction) (fp C.struct_bpf_program) {
	cInsns := make([]C.struct_bpf_insn, len(insns))
	for i := range cInsns {
		cInsns[i].code = C.u_short(insns[i].Op)
		cInsns[i].jf = C.u_char(insns[i].Jf)
		cInsns[i].jt = C.u_char(insns[i].Jt)
		cInsns[i].k = C.uint(insns[i].K)
	}
	fp.bf_len = C.uint(len(insns))
	fp.bf_insns = &cInsns[0]
	return fp
}

// pcapFilterTest filters given packet through filter "repeat" times.
func pcapFilterTest(pkt []byte, snaplen int, expr string, repeat int) (int, error) {
	insns, err := compileBPF(snaplen, expr)
	if err != nil {
		return 0, err
	}

	fp := makeProgram(insns)

	var hdr C.struct_pcap_pkthdr
	hdr.caplen = C.uint(len(pkt))
	hdr.len = hdr.caplen

	return int(C.go_bpf_test(C.uintptr_t(uintptr(unsafe.Pointer(&fp))),
		&hdr, (*C.u_char)(&pkt[0]), C.int(repeat))), nil
}

// SetBPFInstructions sets Berkeley Packet Filter on a
// RingReceiver.
// The BPF is represented as an array of instructions.
//
// If len(insns) == 0, unset the filter.
//
// See SetBPF on notes and caveats.
func (rr *RingReceiver) SetBPFInstructions(insns []bpf.RawInstruction) error {
	rr.reqMany.fp = makeProgram(insns)
	return nil
}

// SetBPF sets Berkeley Packet Filter on a RingReceiver.
//
// The installed BPF will be matched across every packet
// received on it with RingReceiver.Next.
//
// If the pcap_offline_filter returns zero, RingReceiver.Next
// will silently skip this packet.
//
// SetBPF will silently replace previously set filter.
// You can call this function at any point in your program
// but make sure that there is no concurrent packet reading
// activity on the ring at the moment.
func (rr *RingReceiver) SetBPF(snaplen int, expr string) error {
	insns, err := compileBPF(snaplen, expr)
	if err != nil {
		return err
	}

	return rr.SetBPFInstructions(insns)
}

func compileBPF(snaplen int, expr string) ([]bpf.RawInstruction, error) {
	var fp C.struct_bpf_program
	var p *C.pcap_t

	p = C.pcap_open_dead(C.DLT_EN10MB, C.int(snaplen))
	if p == nil {
		return nil, errors.New("unable to create pcap handle")
	}
	defer C.pcap_close(p)

	cExpr := C.CString(expr)
	defer C.free(unsafe.Pointer(cExpr))

	ret := int(C.pcap_compile(p, &fp, cExpr, 1, C.PCAP_NETMASK_UNKNOWN))
	if ret < 0 {
		return nil, errors.New(C.GoString(C.pcap_geterr(p)))
	}
	defer C.pcap_freecode(&fp)

	insns := make([]bpf.RawInstruction, fp.bf_len)
	C.memcpy(unsafe.Pointer(&insns[0]), unsafe.Pointer(fp.bf_insns),
		C.ulong(fp.bf_len*C.sizeof_struct_bpf_insn))
	return insns, nil
}
