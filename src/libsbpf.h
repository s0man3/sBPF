#define PAGE_SIZE 0x1000

struct sbpf_prog {
	unsigned long long insns;
	unsigned insn_len;
	unsigned insn_cnt;
	void *image;
};

union sbpf_attr {
	struct {
		unsigned long long insns;
		unsigned insn_len;
		unsigned insn_cnt;
		unsigned *uimage;
	};
};
