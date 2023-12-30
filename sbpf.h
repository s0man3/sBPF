#include <linux/types.h>

struct sbpf_attr {
	__u64 *insns;
	__u32 insn_len;
}
