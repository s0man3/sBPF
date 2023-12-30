#include <linux/sbpf.h>
#include <linux/syscalls.h>
#include <linux/moduleloader.h>
#include <linux/errno.h>
#include <asm-generic/page.h>

// TO DO: how to prevent double includes between syscall.c and sbpf.h ?

static int __sys_sbpf(int cmd, struct sbpf_attr __user * uattr, unsigned int size)
{
        int err = 0;
        struct sbpf_attr *attr;
        struct sbpf_prog *prog;

        if (size != sizeof(struct sbpf_attr)) {
                err = -EINVAL;
                goto exit;
        }

        attr = kmalloc(sizeof(struct sbpf_attr));
        if (!attr)
                goto exit;

        if (copy_from_user(attr, uattr, size)) {
                err = -EFAULT;
                goto err_attr;
        }

        if (attr->insn_len > PAGE_SIZE)
                goto err_attr;

        prog = kmalloc(sizeof(struct sbpf));
        if (!prog) 
                goto err_attr;

        prog->insns = attr->insns;
        prog->insn_len = attr->insn_len;
        prog->insn_cnt = attr->insn_cnt;
        prog->image = module_alloc(PAGE_SIZE);
        if (!prog->image)
                goto err_prog;


err_prog:
        kfree(prog);
err_attr:
        kfree(attr);
exit:
        if (err == 0)
                err = -ENOMEM;
        return err;
}

SYSCALL_DEFINE3(sbpf, int, cmd, struct sbpf_attr __user *, uattr, unsigned int, size)
{
        return __sys_sbpf(cmd, struct sbpf_attr __user * uattr, size);
}
