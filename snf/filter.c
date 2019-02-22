#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <filter.h>

int go_bpf_make(int n_insns, struct bpf_insn *insns, struct bpf_program *fp)
{
	if (n_insns == 0) {
		go_bpf_delete(fp);
		return 0;
	}

	size_t len = sizeof(*insns) * n_insns;
	struct bpf_insn *new_insns = malloc(len);
	if (new_insns == NULL)
		return ENOMEM;

	go_bpf_delete(fp);
	fp->bf_len = n_insns;
	fp->bf_insns = new_insns;
	memcpy(new_insns, insns, len);
	return 0;
}

void go_bpf_delete(struct bpf_program *fp)
{
	if (fp->bf_len > 0) {
		free(fp->bf_insns);
		fp->bf_len = 0;
	}
}

int go_bpf_test(struct bpf_program *fp,
	   const struct pcap_pkthdr *hdr, const u_char * pkt, int count)
{
	int n, res;
	for (n = 0; n < count; n++)
		res = pcap_offline_filter(fp, hdr, pkt);

	return res;
}