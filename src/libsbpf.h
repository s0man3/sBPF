struct sbpf_prog {
	unsigned long long insns;
	unsigned insn_len;
	unsigned insn_cnt;
	void *image;
};

struct sbpf_attr {
	unsigned long long insns;
	unsigned insn_len;
	unsigned insn_cnt;
};
