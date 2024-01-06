#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "libsbpf.h"

static char call_bytecode[] = "\x85\x00\x00\x00\x00\x00\x00\x00";

int main() {
        int i;
        int ret;
        union sbpf_attr *attr;
        void *stuff;
        char *uim;
        attr = malloc(sizeof(union sbpf_attr));

        stuff = malloc(0x20);
        memcpy(stuff, call_bytecode, 0x8);
        memcpy(stuff + 0x8, call_bytecode, 0x8);
        memcpy(stuff + 0x10, call_bytecode, 0x8);
        memcpy(stuff + 0x18, call_bytecode, 0x8);
        attr->insns = (long long unsigned)stuff;
        attr->insn_len = 0x20;
        attr->insn_cnt = 0x20 / 0x8;
        attr->uimage = malloc(0x1000);

        ret = syscall(548, 0, attr, sizeof(union sbpf_attr));

        printf("Argument:\n"
               "sbpf_attr size:%lu\n"
               "  attr->insns = 0x%llx\n"
               "  attr->insn_len = %u\n"
               "  attr->insn_cnt = %u\n"
               " Return value: %d\n",
               sizeof(union sbpf_attr), attr->insns, attr->insn_len,
               attr->insn_cnt, ret);
        
        uim = (char*)attr->uimage;
        printf("Binary: [");
        for (i=0;i<0x40;i++) {
                printf("%02X", *(unsigned char*)(uim + i));
        }
        printf("]\n");
        printf("i:20 %02X\n", *(unsigned char*)(attr->uimage + 20));

        free(attr->uimage);
        free(stuff);
        free(attr);

        return 0;
}
