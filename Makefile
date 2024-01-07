KERNEL = 

all:
mkdir -p $(KERNEL)/sbpf
cp src/syscall.c src/helpers.c Kbuild <KENREL>/sbpf
cp src/sbpf.h $(KERNEL)/include/linux
cp src/syscall_64.tbl $(KERNEL)/arch/x86/entry/syscalls/syscall_64.tbl
cp src/syscall_64.c $(KERNEL)/include/linux/syscalls.h
cd $(KERNEL)
echo "obj-y += sbpf/" >> Kbuild
make x86_64_defconfig
make -j$(nproc)
