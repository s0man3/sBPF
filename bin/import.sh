mkdir -p mnt
sudo mount rootfs.ext4 mnt
sudo cp user_sbpf mnt/root
sudo umount mnt
rmdir mnt

