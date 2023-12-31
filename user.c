#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdlib.h>

#include "libsbpf.h"

int main() {
        int ret;
        struct sbpf_attr *attr;
        void *stuff;
        attr = malloc(sizeof(attr));
        stuff = malloc(0x20);

        attr->insns = stuff;
        attr->insn_len = 0x20;
        attr->insn_cnt = 0x20 / 0x8;
        ret = syscall(548, attr, sizeof(attr));

        printf("Argument:\n"
               "  attr->insns = %llx\n"
               "  attr->insn_len = %u\n"
               "  attr->insn_cnt = %u\n"
               " Return value: %u\n",
               attr->insns, attr->insn_len,
               attr->insn_cnt, ret);

        free(attr);
        free(stuff);

        return 0;
}
