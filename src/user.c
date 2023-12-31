#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdlib.h>

#include "libsbpf.h"

int main() {
        int ret;
        struct sbpf_attr *attr;
        void *stuff;
        attr = malloc(sizeof(struct sbpf_attr));
        stuff = malloc(0x20);

        attr->insns = stuff;
        attr->insn_len = 0x20;
        attr->insn_cnt = 0x20 / 0x8;
        ret = syscall(548, 0, attr, sizeof(struct sbpf_attr));

        printf("Argument:\n"
               "sbpf_attr size:%lu\n"
               "  attr->insns = 0x%llx\n"
               "  attr->insn_len = %u\n"
               "  attr->insn_cnt = %u\n"
               " Return value: %d\n",
               sizeof(struct sbpf_attr), attr->insns, attr->insn_len,
               attr->insn_cnt, ret);

        free(attr);
        free(stuff);

        return 0;
}
