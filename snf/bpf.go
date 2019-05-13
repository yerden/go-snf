// Copyright 2019 Yerden Zhumabekov. All rights reserved.
//
// Use of this source code is governed by MIT license which
// can be found in the LICENSE file in the root of the source
// tree.

package snf

/*
#include <stdint.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <snf.h>

int go_bpf_test(uintptr_t pfp, const struct pcap_pkthdr *hdr,
		const u_char * pkt, int count)
{
	int n, res;
	struct bpf_program *fp = (typeof(fp))pfp;
	for (n = 0; n < count; n++)
		res = pcap_offline_filter(fp, hdr, pkt);

	return res;
}

void exec_bpf(int n_insns, struct bpf_insn *insns,
	int n_reqs, struct snf_recv_req *reqs, int32_t *out) {
	struct bpf_program fp = {
		.bf_len = n_insns,
		.bf_insns = insns,
	};

	int i;
	for (i = 0; i < n_reqs; i++) {
		struct snf_recv_req *req = &reqs[i];
		struct pcap_pkthdr hdr = {
			.caplen = req->length,
			.len = req->length,
		};
		out[i] = pcap_offline_filter(&fp, &hdr, req->pkt_addr);
	}
}
*/
import "C"

import (
	"errors"
	"unsafe"

	"golang.org/x/net/bpf"
)

func makeProgram(insns []bpf.RawInstruction) (fp C.struct_bpf_program) {
	cInsns := make([]C.struct_bpf_insn, len(insns))
	C.memcpy(unsafe.Pointer(&cInsns[0]), unsafe.Pointer(&insns[0]),
		C.ulong(len(insns)*C.sizeof_struct_bpf_insn))
	fp.bf_len = C.uint(len(insns))
	fp.bf_insns = &cInsns[0]
	return fp
}

// pcapFilterTest filters given packet through filter "repeat" times.
func pcapFilterTest(pkt []byte, snaplen int, expr string, repeat int) (int, error) {
	insns, err := CompileBPF(snaplen, expr)
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

// CompileBPF prepared BPF machine instructions ready for execution.
func CompileBPF(snaplen int, expr string) ([]bpf.RawInstruction, error) {
	var fp C.struct_bpf_program

	p := C.pcap_open_dead(C.DLT_EN10MB, C.int(snaplen))
	if p == nil {
		return nil, errors.New("unable to create pcap handle")
	}
	defer C.pcap_close(p)

	cExpr := C.CString(expr)
	defer C.free(unsafe.Pointer(cExpr))

	if C.pcap_compile(p, &fp, cExpr, 1, C.PCAP_NETMASK_UNKNOWN) < 0 {
		return nil, errors.New(C.GoString(C.pcap_geterr(p)))
	}
	defer C.pcap_freecode(&fp)

	insns := make([]bpf.RawInstruction, fp.bf_len)
	C.memcpy(unsafe.Pointer(&insns[0]), unsafe.Pointer(fp.bf_insns),
		C.ulong(fp.bf_len*C.sizeof_struct_bpf_insn))
	return insns, nil
}

// ExecuteBPF runs BPF instructions on array of RecvReq. The output
// will be put in res array which should be able to contain at least
// len(reqs) elements. Otherwise, it will panic.
func ExecuteBPF(insns []bpf.RawInstruction, reqs []RecvReq, res []int32) {
	if len(res) < len(reqs) {
		panic("insufficient room for output")
	}

	bpfLen, bpfPtr := C.int(len(insns)), (*C.struct_bpf_insn)(unsafe.Pointer(&insns[0]))
	reqLen, reqPtr := C.int(len(reqs)), (*C.struct_snf_recv_req)(&reqs[0])
	C.exec_bpf(bpfLen, bpfPtr, reqLen, reqPtr, (*C.int)(&res[0]))
}
