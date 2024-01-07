#include <linux/sbpf.h>
#include <linux/syscalls.h>
#include <linux/moduleloader.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/printk.h>
#include <linux/idr.h>
#include <linux/set_memory.h>

// Syscall Number: 548 (defined in arch/x86/entry/syscalls/syscall_64.tbl)

static DEFINE_SPINLOCK(prog_idr_lock);
static DEFINE_IDR(prog_idr);

noinline u64 __sbpf_call_base(void)
{
        return 0;
}

static int sbpf_attach(union sbpf_attr *attr)
{
        struct sbpf_prog *prog;
        struct kprobe *kp;
        char *temp;
        int err;

        prog = idr_find(&prog_idr, attr->id);
        if (!prog) {
                err = -EINVAL;
                goto exit;
        }

        kp = kzalloc(sizeof(struct kprobe), GFP_KERNEL);
        if (!kp)
                goto exit;

        kp->pre_handler = (void*)prog->image;

        temp = kzalloc(0x20, GFP_KERNEL);
        if (!temp) 
                goto err_kp;
        strlcpy(temp, attr->kprobe_name, 0x20);

        kp->symbol_name = temp;

        prog->kp = kp;

        err = register_kprobe(kp);
        if (err < 0) {
                printk(KERN_ERR "sbpf:register_kprobe failed");
                prog->kp = NULL;
                goto err_sym;
        }

        return err;

err_sym:
        kfree(kp->symbol_name);
err_kp:
        kfree(kp);
exit:
        if (err == 0)
                err = -ENOMEM;
        return err;
}

static int sbpf_detach(union sbpf_attr *attr) {
        struct sbpf_prog *prog;
        struct kprobe *kp;
        int err = 0;

        prog = idr_find(&prog_idr, attr->id);
        if (!prog) {
                err = -EINVAL;
                goto exit;
        }

        kp = prog->kp;

        if (!kp) {
                err = -EINVAL;
                goto exit;
        }

        unregister_kprobe(kp);
        kfree(kp->symbol_name);
        kfree(kp);

        prog->kp = NULL;

        return 0;
exit:
        return err;
}

static int replace_helper(struct sbpf_insn *insn) {
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
                                        ret = replace_helper(insn);
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

        prog_len += 1;
        prog_len += 2;
        if (prog_len >= PAGE_SIZE)
                ret = -1;

        return ret;
}

static void emit_ret(u8 *temp) {
        *temp = 0xC3;
        temp += 1;
        return;
}

static void emit_call(u8 *temp, u8 *func, u8 *addr) {
        *temp = 0xE8;
        temp += 1;
        *(s32 *)temp = (s32)(func - addr - 5);
        temp += 4;
        return;
}

static void emit_xor_rax(u8 *temp) {
        *temp = 0x31;
        temp += 1;
        *temp = 0xC0;
        temp += 1;
        return;
}


static int do_jit(struct sbpf_prog *prog) {
        int insn_cnt = prog->insn_cnt;
        struct sbpf_insn *insn = prog->insns;
        u8 temp[SBPF_MAX_INSN_SIZE + SBPF_INSN_SAFETY];
        u8 *head;
        int templen, ilen = 0;
        int i = 0, err = 0;
        prog->im_len = 0;

        for (i = 0; i < insn_cnt; i++, insn++) {
                u8 *func;
                switch(insn->code) {
                        case SBPF_JMP | SBPF_CALL:
                                func = (u8 *) __sbpf_call_base + insn->imm;
                                emit_call(head, func, prog->image + ilen);
                                templen += 5;
                                break;
                }
                if (err)
                        break;
                memcpy(prog->image + ilen, temp, templen);
                ilen += templen;
                prog->im_len += templen;
                templen = 0;
                head = temp;
        }

        emit_xor_rax(head);
        templen = 2;
        memcpy(prog->image + ilen, temp, templen);
        ilen += templen;
        prog->im_len += templen;

        templen = 0;
        head = temp;

        emit_ret(head);
        templen = 1;
        memcpy(prog->image +  ilen, temp, templen);
        prog->im_len += templen;

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

        prog->kp = NULL;

        err = do_check(prog);
        err = err ?: do_jit(prog);

        if(err) {
                err = -EFAULT;
                goto err_module;
        }

        set_memory_x((u64)prog->image, 1);

        spin_lock_bh(&prog_idr_lock);
        id = idr_alloc_cyclic(&prog_idr, prog, 1, INT_MAX, GFP_ATOMIC);
        prog->id = id;
        spin_unlock_bh(&prog_idr_lock);
        if (id < 0) {
                err = -EFAULT;
                goto err_module;
        }

        printk(KERN_INFO "sBPF loaded\n"
                         "  program id  : %d\n"
                         "  jit code length : %d\n"
                         "  loaded at : %llx",
                         prog->id, prog->im_len, (u64)prog->image);

        if (copy_to_user(attr->uimage, prog->image, prog->im_len)) {
                err = -EFAULT;
                goto err_module;
        }

        return 0;

err_module:
        module_memfree(prog->image);
err_insns:
        kfree(prog->insns);
err_prog:
        kfree(prog);
exit:
        if (err == 0)
                err = -ENOMEM;
        return err;
}

static int sbpf_prog_unload(union sbpf_attr *attr) {
        struct sbpf_prog *prog;
        int err = 0;

        prog = idr_find(&prog_idr, attr->id);
        if (!prog) {
                err = -EINVAL;
                goto exit;
        }

        if (!prog->kp) {
                sbpf_detach(attr);
        }

        spin_lock_bh(&prog_idr_lock);
        idr_remove(&prog_idr, prog->id);
        spin_unlock_bh(&prog_idr_lock);

        module_memfree(prog->image);
        kfree(prog->insns);
        kfree(prog);

        printk(KERN_INFO "sbpf: successfully unloaded");

        return 0;
exit:
        return err;
}

static int __sys_sbpf(int cmd, union sbpf_attr __user * uattr, unsigned int size)
{
        int err = 0;
        union sbpf_attr *attr;

        attr = kmalloc(sizeof(union sbpf_attr), GFP_KERNEL);
        if (!attr)
                goto exit;


        if (copy_from_user(attr, uattr, size)) {
                err = -EFAULT;
                goto err_attr;
        }

        if (cmd == 0)
                printk(KERN_INFO "In sbpf:\n"
                                 "cmd : %d\n"
                                 "union sbpf_attr size: %lu\n"
                                 "  insns(addr) : 0x%llx\n"
                                 "  insn_len    : %u\n"
                                 "  insn_cnt    : %u",
                                 cmd, sizeof(union sbpf_attr), attr->insns, attr->insn_len, attr->insn_cnt);
        else if (cmd == 1)
                printk(KERN_INFO "In sbpf:\n"
                                 "cmd : %d\n"
                                 "  id  : %d\n"
                                 "  kprobe_name : %s",
                                 cmd, attr->id, attr->kprobe_name);
        else
                printk(KERN_INFO "In sbpf:\n"
                                 "cmd : %d", cmd);

        switch(cmd) {
                case 0:
                        err = sbpf_prog_load(attr);
                        break;
                case 1:
                        err = sbpf_attach(attr);
                        break;
                case 2:
                        err = sbpf_prog_unload(attr);
                        break;
                case 3:
                        err = sbpf_detach(attr);
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
