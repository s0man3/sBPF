tiny Selfmade BPF, supporting calls for helper fuctions.

# Installation

git clone linux kernel and checkout to your convenience.
```
write KERNEL path to Makefile.
make
```
or
```
mkdir <KERNEL>/sbpf
cp src/syscall.c src/helpers.c Kbuild <KERNEL>/sbpf
cp src/sbpf.h <KERNEL>/include/linux
cp src/syscall_64.tbl <KERNEL>/arch/x86/entry/syscalls/syscall_64.tbl
cp src/syscall_64.c <KERNEL>/include/linux/syscalls.h
cd <KERNEL>
echo "obj-y += sbpf/" >> Kbuild
make menuconfig (x86_64_defconfig etc)
make -j$(nproc)
```
If syscall interfaces differ from v6.6.9, edit syscall_64.tbl and syscalls.h mannually.

# Run
```
cd bin
./start-qemu
./user_sbpf (load and attach a sample program)
```
