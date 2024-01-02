#include <linux/sbpf.h>
#include <linux/types.h>
#include <linux/sched.h>

static u64 sbpf_get_current_pid_tgid(void)
{
        struct task_struct *task = current;

        if (unlikely(!task))
                return -EINVAL;

        return (u64) task->tgid << 32 | task->pid;
}

const struct sbpf_func_proto sbpf_get_current_pid_tgid_proto = {
        .func = sbpf_get_current_pid_tgid,
};

const struct sbpf_func_proto * get_sbpf_func_proto(__s32 id) {
        switch(id) {
                case 0:
                        return &sbpf_get_current_pid_tgid_proto;
        }

        return NULL;
}
