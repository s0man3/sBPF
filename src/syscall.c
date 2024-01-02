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

noinline u64 __sbpf_call_base(void)
{
        return 0;
}


static int emit_helper_addr(struct sbpf_insn *insn) {
        const struct sbpf_func_proto *fn;
        switch(insn->imm) {
                case 0:
                        fn = get_sbpf_func_proto(insn->imm);
                        insn->imm = fn->func - __sbpf_call_base;
                        return 0;
        }
        return -1;
}

static int do_check(struct sbpf_prog *prog) {
        int insn_cnt = prog->insn_cnt;
        struct sbpf_insn *insn = prog->insns;
        int prog_len = 0;
        int i, ret;

        for (i = 0; i < insn_cnt; i++, insn++) {
                switch(insn->code) {
                        case SBPF_JMP | SBPF_CALL:
                                if (insn->src_reg == 0) {
                                        ret = emit_helper_addr(insn);
                                        prog_len += 5;
                                } else
                                        ret = -1;
                                break;
                        default:
                                ret = -1;
                }
                if (ret)
                        break;
                if (prog_len >= PAGE_SIZE) {
                        ret = -1;
                        break;
                }
        }
        return ret;
}

static void emit_call(u8 *temp, __s32 imm) {
        *temp = 0xE8;
        temp += 1;
        *(s32 *)temp = imm;
        temp += 4;
        return;
}

static int do_jit(struct sbpf_prog *prog) {
        int insn_cnt = prog->insn_cnt;
        struct sbpf_insn *insn = prog->insns;
        u8 temp[SBPF_MAX_INSN_SIZE + SBPF_INSN_SAFETY];
        int templen, ilen = 0;
        int i = 0, err = 0;
        prog->im_len = 0;

        for (i = 0; i < insn_cnt; i++, insn++) {
                switch(insn->code) {
                        case SBPF_JMP | SBPF_CALL:
                                emit_call(temp, insn->imm);
                                templen += 5;
                                break;
                }
                if (err)
                        break;
                memcpy(prog->image + ilen, temp, templen);
                ilen += templen;
                prog->im_len += templen;
                templen = 0;
        }

        printk(KERN_INFO "sBPF iterator : %d", i);

        return err;
}

static int sbpf_prog_load(union sbpf_attr *attr)
{
        int err = 0;
        struct sbpf_prog *prog;
        int id = 0;

        prog = kmalloc(sizeof(struct sbpf_prog), GFP_KERNEL);
        if (!prog) 
                goto exit;

        prog->insns = kmalloc(attr->insn_len, GFP_KERNEL);
        if (!prog->insns)
                goto err_prog;

        prog->insn_len = attr->insn_len;
        prog->insn_cnt = attr->insn_cnt;
        prog->im_len = 0;

        if (copy_from_user(prog->insns, (void*)attr->insns, attr->insn_len)) {
                err = -EFAULT;
                goto err_insns;
        }

        prog->image = module_alloc(PAGE_SIZE);
        if (!prog->image) 
                goto err_insns;

        err = do_check(prog);
        err = err ?: do_jit(prog);

        if(err) {
                err = -EFAULT;
                goto err_insns;
        }

        spin_lock_bh(&prog_idr_lock);
        id = idr_alloc_cyclic(&prog_idr, prog, 1, INT_MAX, GFP_ATOMIC);
        if (id > 0)
                prog->id = id;
        spin_unlock_bh(&prog_idr_lock);

        printk(KERN_INFO "sBPF loaded:"
                         "  program id : %d\n"
                         "  jit code length : %d\n",
                         prog->id, prog->im_len);

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
