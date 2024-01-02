#include <linux/types.h>

static u64 sbpf_get_current_pid_tgid(void)
{
        return 0;
}

const struct sbpf_func_proto sbpf_get_current_pid_tgid_proto = {
        u64 *func;
};

struct sbpf_func_proto * get_sbpf_func_proto(__s16 id) {
        switch(id) {
                case 0:
                        return &sbpf_get_current_pid_tgid_proto;
                        break;
        }

        return NULL;
}
