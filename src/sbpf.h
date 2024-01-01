#include <linux/types.h>

struct sbpf_prog {
	void	*insns;
	__u32	insn_len;
	__u32	insn_cnt;
	void	*image;
	int id;
};

union sbpf_attr {
	struct {
		__u64	insns;
		__u32	insn_len;
		__u32	insn_cnt;
	};
};
