#include <linux/types.h>
#include <linux/kprobes.h>

#define SBPF_MAX_INSN_SIZE	128
#define SBPF_INSN_SAFETY	64

#define SBPF_CALL		0x80
#define SBPF_JMP		0x5

#define SBPF_NAME_LIMIT	0x20

struct sbpf_insn {
	__u8	code;
	__u8	dst_reg:4;
	__u8	src_reg:4;
	__s16	off;
	__s32	imm;
};

struct sbpf_prog {
	struct sbpf_insn	*insns;
	__u32	insn_len;
	__u32	insn_cnt;
	void	*image;
	__s32	im_len;
	struct kprobe *kp;
	int id;
};

union sbpf_attr {
	struct {
		__u64	insns;
		__u32	insn_len;
		__u32	insn_cnt;
		__u8	*uimage;
	};

	struct {
		int	id;
		char kprobe_name[SBPF_NAME_LIMIT];
	};
};

struct sbpf_func_proto {
	u64 (*func)(void);
};

extern const struct sbpf_func_proto * get_sbpf_func_proto(__s32 id);
