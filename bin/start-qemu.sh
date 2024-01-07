qemu-system-x86_64 -s -boot c -m 1024M -kernel ./bzImage -hda ./rootfs.ext4 -append "root=/dev/sda rw console=ttyS0,115200 acpi=off nokaslr" -serial stdio -display none
