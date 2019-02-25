#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <filter.h>

int go_bpf_make(unsigned int n_insns, struct bpf_insn *insns, struct bpf_program **pfp)
{
	struct bpf_program *fp;
	struct bpf_insn *new_insns;
	size_t len = sizeof(*insns) * n_insns;

	if ((fp = malloc(sizeof(*fp))) == NULL)
		return ENOMEM;

	if ((new_insns = malloc(len)) == NULL) {
		free(fp);
		return ENOMEM;
	}

	fp->bf_len = n_insns;
	fp->bf_insns = new_insns;
	memcpy(new_insns, insns, len);
	*pfp = fp;
	return 0;
}

void go_bpf_delete(struct bpf_program *fp)
{
	if (fp)
		free(fp->bf_insns);
	free(fp);
}

int go_bpf_test(uintptr_t pfp, const struct pcap_pkthdr *hdr,
		const u_char * pkt, int count)
{
	int n, res;
	struct bpf_program *fp = (typeof(fp))pfp;
	for (n = 0; n < count; n++)
		res = pcap_offline_filter(fp, hdr, pkt);

	return res;
}
