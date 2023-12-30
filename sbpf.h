#include <linux/types.h>

struct sbpf_prog {
	__u64 *insns;
	__u32 insn_len;
	__u64 *image;
}

struct sbpf_attr {
	__u64 *insns;
	__u32 insn_len;
}
