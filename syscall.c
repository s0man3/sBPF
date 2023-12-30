#include <linux/sbpf.h>
#include <linux/syscalls.h>

static int __sys_sbpf(int cmd, struct sbpf_attr __user * uattr, unsigned int size)
{
        int err = 0;
        return err;
}

SYSCALL_DEFINE3(sbpf, int, cmd, struct sbpf_attr __user *, uattr, unsigned int, size)
{
        return __sys_sbpf(cmd, struct sbpf_attr __user * uattr, size);
}
