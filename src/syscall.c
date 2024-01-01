#include <linux/sbpf.h>
#include <linux/syscalls.h>
#include <linux/moduleloader.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/printk.h>
#include <linux/idr.h>

// Syscall Number: 548 (defined in arch/x86/entry/syscalls/syscall_64.tbl)

static DEFINE_SPINLOCK(prog_idr_lock);
static DEFINE_IDR(prog_idr);

static int sbpf_prog_load(union sbpf_attr *attr)
{
        int err = 0;
        struct sbpf_prog *prog;
        int id = 0;

        if (attr->insn_len > PAGE_SIZE) {
                err = -EINVAL;
                goto exit;
        }

        prog = kmalloc(sizeof(struct sbpf_prog), GFP_KERNEL);
        if (!prog) 
                goto exit;

        prog->insns = kmalloc(attr->insn_len, GFP_KERNEL);
        if (!prog->insns)
                goto err_prog;

        prog->insn_len = attr->insn_len;
        prog->insn_cnt = attr->insn_cnt;

        if (copy_from_user(prog->insns, (void*)attr->insns, attr->insn_len)) {
                err = -EFAULT;
                goto err_insns;
        }

        prog->image = module_alloc(PAGE_SIZE);
        if (!prog->image) 
                goto err_insns;

        spin_lock_bh(&prog_idr_lock);
        id = idr_alloc_cyclic(&prog_idr, prog, 1, INT_MAX, GFP_ATOMIC);
        if (id > 0)
                prog->id = id;
        spin_unlock_bh(&prog_idr_lock);

        if (id > 0) {
                spin_lock_bh(&prog_idr_lock);
                idr_remove(&prog_idr, id);
                spin_unlock_bh(&prog_idr_lock);
        }
        
        module_memfree(prog->image);
        kfree(prog->insns);
        kfree(prog);

        return 0;

err_insns:
        kfree(prog->insns);
err_prog:
        kfree(prog);
exit:
        if (err == 0)
                err = -ENOMEM;
        return err;
}


static int __sys_sbpf(int cmd, union sbpf_attr __user * uattr, unsigned int size)
{
        int err = 0;
        union sbpf_attr *attr;

        if (size != sizeof(union sbpf_attr)) {
                err = -EINVAL;
                goto exit;
        }

        attr = kmalloc(sizeof(union sbpf_attr), GFP_KERNEL);
        if (!attr)
                goto exit;


        if (copy_from_user(attr, uattr, size)) {
                err = -EFAULT;
                goto err_attr;
        }

        printk(KERN_INFO "In sbpf:\n"
                         "union sbpf_attr size: %lu\n"
                         "  insns(addr) : 0x%llx\n"
                         "  insn_len    : %u\n"
                         "  insn_cnt    : %u",
                         sizeof(union sbpf_attr), attr->insns, attr->insn_len, attr->insn_cnt);

        switch(cmd) {
                case 0:
                        err = sbpf_prog_load(attr);
                        break;
        }

        return err;

err_attr:
        kfree(attr);
exit:
        if (err == 0)
                err = -ENOMEM;
        return err;
}

SYSCALL_DEFINE3(sbpf, int, cmd, union sbpf_attr __user *, uattr, unsigned int, size)
{
        return __sys_sbpf(cmd, uattr, size);
}
