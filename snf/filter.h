#ifndef _FILTER_H_
#define _FILTER_H_

#include <stdint.h>
#include <pcap.h>

void go_bpf_delete(struct bpf_program *fp);
int go_bpf_make(unsigned int n_insns, struct bpf_insn *insns, struct bpf_program **fp);
int go_bpf_test(uintptr_t pfp, const struct pcap_pkthdr *hdr,
		const u_char * pkt, int count);

#endif				/* _FILTER_H_ */
