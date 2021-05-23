#!/usr/bin/bash

if [ $UID -ne 0 ]; then
    echo "You MUST be root to do this!" 1>&2
    exit 1
fi

if [ $# -lt 3 ]; then
    echo "$0 <tar image> <uboot dir> <disk> [source script]" 1>&2
    exit 1
fi

DISK="$3"
IMAGE="$1"
UBOOT="$2"
SCRIPT="$4"
ROOT="/tmp/$(date +%s)-root"
SYSCONFIG_DIR="/opt/sysconfig"

exec() {
    if [ $# -lt 1 ]; then
        return
    fi
    eval $1 1>/dev/null; r=$?
    if [ $# -eq 1 ]; then
        if [ $r -eq 0 ]; then
            return
        fi
        echo -e "\033[1;31mCommand \033[0m\"${1}\"\033[1;31m exited witn a non-zero \033[0m(${r})\033[1;31m status code!\033[0m" 1>&2
        cleanup 1
    fi
    if [ $r -ne $2 ]; then
        echo -e "\033[1;31mCommand \033[0m\"${1}\"\033[1;31m exited with a \033[0m\"${r}\"\033[1;31m status code!\033[0m" 1>&2
        cleanup 1
    fi
}
print() {
    echo -e -n "\033[1;32m"
    echo $*
    echo -e -n "\033[0m"
}
checks() {
    which dd 1> /dev/null 2> /dev/null
    if [ $? -ne 0 ]; then
        echo -e '\033[1;31m"\033[0mdd" is missing, please install "\033[0mcoreutils\033[1;31m" first!\033[0m' 1>&2
        exit 1
    fi
    which lsof 1> /dev/null 2> /dev/null
    if [ $? -ne 0 ]; then
        echo -e '\033[1;31m"\033[0mlsof\033[1;31m" is missing, please install "\033[0mlsof\033[1;31m" first!\033[0m' 1>&2
        exit 1
    fi
    which bsdtar 1> /dev/null 2> /dev/null
    if [ $? -ne 0 ]; then
        echo -e '\033[1;31m"\033[0mbsdtar\033[1;31m" is missing, please install "\033[0mlibarchive\033[1;31m" first!\033[0m' 1>&2
        exit 1
    fi
    which mkimage 1> /dev/null 2> /dev/null
    if [ $? -ne 0 ]; then
        echo -e '\033[1;31m"\033[0mmkimage\033[1;31m" is missing, please install "\033[0muboot-tools\033[1;31m" first!\033[0m' 1>&2
        exit 1
    fi
    which mkfs.ext4 1> /dev/null 2> /dev/null
    if [ $? -ne 0 ]; then
        echo -e '\033[1;31m"\033[0mmkfs.ext4\033[1;31m" is missing, please install "\033[0me2fsprogs\033[1;31m" first!\033[0m' 1>&2
        exit 1
    fi
    which mkfs.btrfs 1> /dev/null 2> /dev/null
    if [ $? -ne 0 ]; then
        echo -e '\033[1;31m"\033[0mmkfs.btrfs\033[1;31m" is missing, please install "\033[0mbtrfs-progs\033[1;31m" first!\033[0m' 1>&2
        exit 1
    fi
    which qemu-arm-static 1> /dev/null 2> /dev/null
    if [ $? -ne 0 ]; then
        echo -e '\033[1;31m"\033[0mqemu-arm-static\033[1;31m" is missing, please install "\033[0mqemu-user-static\033[1;31m" first!\033[0m' 1>&2
        exit 1
    fi
    if ! [ -f "$DISK" ]; then
        echo -e "\033[1;31mPath \"\033[0m${DISK}\033[1;31m\" is not a block device!\033[0m" 1>&2
        exit 1
    fi
    if ! [ -f "$IMAGE" ]; then
        echo -e "\033[1;31mImage path \"\033[0m${IMAGE}\033[1;31m\" does not exist!\033[0m" 1>&2
        exit 1
    fi
    if ! [ -d "$UBOOT" ]; then
        echo -e "\033[1;31mUboot path \"\033[0m${UBOOT}\033[1;31m\" is not a directory!\033[0m" 1>&2
        exit 1
    fi
    if ! [ -f "$UBOOT/MLO" ]; then
        echo -e "\033[1;31mUboot path \"\033[0m${UBOOT}/MLO\033[1;31m\" does not exist!\033[0m" 1>&2
        exit 1
    fi
    if ! [ -f "$UBOOT/u-boot.img" ]; then
        echo -e "\033[1;31mUboot path \"\033[0m${UBOOT}/u-boot.img\033[1;31m\" does not exist!\033[0m" 1>&2
        exit 1
    fi
    if ! [ -f "$(pwd)/config.sh" ]; then
        echo -e "\033[1;31mPath \"\033[0m${pwd}/config.sh\033[1;31m\" does not exist!\033[0m" 1>&2
        exit 1
    fi
}
cleanup() {
    print "Performing cleanup..."
    sync
    umount /proc/sys/fs/binfmt_misc 2> /dev/null
    umount "${ROOT}/var" 2> /dev/null
    umount "${ROOT}" 2> /dev/null
    rmdir "${ROOT}" 2> /dev/null
    if [ $# -ne 1 ]; then
        exit 0
    fi
    exit $1
}

trap cleanup 1 2 3 6

print "Zero-ing out the UBoot sectors..."
exec "dd if=/dev/zero of=${DISK} bs=1M count=8"

total=$(fdisk -l ${DISK}|grep 'Disk'|grep 'sectors'|awk '{print $7}')
if [ $? -ne 0 ]; then
    echo -e "\033[1;31Could not get disk sector size!\033[0m" 1>&2
    cleanup 1
fi
size_root=$((total - 16781312))
size_cache=$((size_root + 16777217))
max_root=$((size_root + 1))

print "Partitioning disk ${DISK}..."
printf "o\nn\np\n1\n4096\n${size_root}\ny\nn\np\n2\n${max_root}\n${size_cache}\ny\nw\n" | exec "fdisk ${DISK}"

print "Creating and formatting partitions..."
exec "mkfs.ext4 -q -L root -F ${DISK}p1"
exec "mkfs.btrfs -L cache -f ${DISK}p2"

print "Mounting partitions..."
exec "mkdir -p ${ROOT}"
exec "mount -t ext4 -o rw,noatime,nodev,discard ${DISK}p1 ${ROOT}"
exec "mkdir -p ${ROOT}/var"
exec "mount -t btrfs -o rw,noatime,nodev,noexec,nosuid,compress=zstd,ssd,discard=async ${DISK}p2 ${ROOT}/var"
exec "btrfs subvolume create ${ROOT}/var/base"
exec "umount ${ROOT}/var"
exec "mount -t btrfs -o rw,noatime,nodev,noexec,nosuid,compress=zstd,ssd,discard=async,subvol=/base ${DISK}p2 ${ROOT}/var"

print "Extracting ${IMAGE} to disk..."
exec "bsdtar -xpf \"${IMAGE}\" -C ${ROOT}"
sync

print "Copying and Installing Uboot..."
rm -f "${ROOT}/boot/MLO" 2> /dev/null
rm -f "${ROOT}/boot/boot.txt" 2> /dev/null
rm -f "${ROOT}/boot/boot.scr" 2> /dev/null
rm -f "${ROOT}/boot/u-boot.img" 2> /dev/null
exec "cp \"${UBOOT}/MLO\" ${ROOT}/boot/MLO"
exec "cp \"${UBOOT}/u-boot.img\" ${ROOT}/boot/u-boot.img"
exec "dd if=${ROOT}/boot/MLO of=${DISK} count=1 seek=1 conv=notrunc bs=128k"
exec "dd if=${ROOT}/boot/u-boot.img of=${DISK} count=2 seek=1 conv=notrunc bs=384k"
sync

mac_addr=$(printf '%x%x:%x%x:%x%x' $(($RANDOM % 10)) $(($RANDOM % 10)) $(($RANDOM % 10)) $(($RANDOM % 10)) $(($RANDOM % 10)) $(($RANDOM % 10)))
printf 'if test -n ${distro_bootpart}; then setenv bootpart ${distro_bootpart}; ' > "${ROOT}/boot/boot.txt"
printf 'else setenv bootpart 1; fi\npart uuid ${devtype} ${devnum}:${bootpart} uuid\n\n' >> "${ROOT}/boot/boot.txt"
printf 'setenv bootargs "console=tty0 console=${console} root=PARTUUID=${uuid} noatime rootwait' >> "${ROOT}/boot/boot.txt"
printf ' ro quiet loglevel=2 rd.systemd.show_status=auto rd.udev.log_priority=2 modules-load=dwc2,g_ether ' >> "${ROOT}/boot/boot.txt"
printf "ipv6.disable=1 g_ether.host_addr=be:ef:ed:${mac_addr} g_ether.dev_addr=${mac_addr}\"" >> "${ROOT}/boot/boot.txt"
printf '\n\nif load ${devtype} ${devnum}:${bootpart} ${kernel_addr_r} /boot/zImage; then\n  gpio set 54\n' >> "${ROOT}/boot/boot.txt"
printf '  echo fdt: ${fdtfile}\n  if load ${devtype} ${devnum}:${bootpart} ${fdt_addr_r} /boot/dtbs/${fdtfile};' >> "${ROOT}/boot/boot.txt"
printf ' then\n    gpio set 55\n    if load ${devtype} ${devnum}:${bootpart} ${ramdisk_addr_r} ' >> "${ROOT}/boot/boot.txt"
printf '/boot/initramfs-linux.img; then\n      gpio set 56\n      bootz ${kernel_addr_r}' >> "${ROOT}/boot/boot.txt"
printf ' ${ramdisk_addr_r}:${filesize} ${fdt_addr_r};\n    else\n      gpio set 56\n' >> "${ROOT}/boot/boot.txt"
printf '      bootz ${kernel_addr_r} - ${fdt_addr_r};\n    fi;\n  fi;\nfi\n' >> "${ROOT}/boot/boot.txt"
exec "mkimage -A arm -O linux -T script -C none -n 'U-Boot boot script' -d ${ROOT}/boot/boot.txt ${ROOT}/boot/boot.scr"

print "Preparing supplimantary files..."
# Fix DNS Config issue
rm "${ROOT}/etc/resolv.conf"
cp -fL "/etc/resolv.conf" "${ROOT}/etc/resolv.conf"

# /etc/sysconfig.conf
printf "SYSCONFIG=${SYSCONFIG_DIR}\n" > "${ROOT}/etc/sysconfig.conf"

# /root/init.sh
printf '#!/usr/bin/bash\n\n' > "${ROOT}/root/init.sh"
printf 'pacman-key --init\n' >> "${ROOT}/root/init.sh"
printf 'pacman-key --populate archlinuxarm\n' >> "${ROOT}/root/init.sh"
printf 'pacman -Syy --noconfirm\n' >> "${ROOT}/root/init.sh"
printf 'pacman -Syu --noconfirm\n' >> "${ROOT}/root/init.sh"
printf "bash ${SYSCONFIG_DIR}/bin/relink ${SYSCONFIG_DIR} /\n" >> "${ROOT}/root/init.sh"
printf "bash ${SYSCONFIG_DIR}/bin/syslink\n" >> "${ROOT}/root/init.sh"
printf 'pacman -S dnsmasq btrfs-progs pacman-contrib zstd --noconfirm\n' >> "${ROOT}/root/init.sh"
printf 'mount -o rw,remount /\n' >> "${ROOT}/root/init.sh"
printf 'systemctl mask rescue.service > /dev/null\n' >> "${ROOT}/root/init.sh"
printf 'systemctl mask emergency.service > /dev/null\n' >> "${ROOT}/root/init.sh"
printf 'systemctl mask emergency.target > /dev/null\n' >> "${ROOT}/root/init.sh"
printf 'systemctl disable systemd-resolved > /dev/null\n' >> "${ROOT}/root/init.sh"
printf 'rm /etc/systemd/system/multi-user.target.wants/systemd-resolved.service 2> /dev/null\n' >> "${ROOT}/root/init.sh"
printf 'rm /etc/systemd/system/dbus-org.freedesktop.resolve1.service 2> /dev/null\n' >> "${ROOT}/root/init.sh"
printf 'systemctl enable systemd-networkd.service > /dev/null\n' >> "${ROOT}/root/init.sh"
printf 'systemctl enable systemd-timesyncd.service > /dev/null\n' >> "${ROOT}/root/init.sh"
printf 'systemctl enable dnsmasq.service > /dev/null\n' >> "${ROOT}/root/init.sh"
printf 'systemctl enable fstrim.timer > /dev/null\n' >> "${ROOT}/root/init.sh"
printf 'ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N "" < /dev/null > /dev/null\n' >> "${ROOT}/root/init.sh"
printf 'ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N "" < /dev/null > /dev/null\n' >> "${ROOT}/root/init.sh"
printf 'chmod 400 /etc/ssh/*_key\n' >> "${ROOT}/root/init.sh"
if [ ! -z "$SCRIPT" ] && [ -f $SCRIPT ]; then
    print "Addding addditional script \"${SCRIPT}\"..."
    cp "$SCRIPT" "${ROOT}/root/extra.sh"
    chmod 500 "${ROOT}/root/extra.sh"
    printf 'bash /root/extra.sh\n' >> "${ROOT}/root/init.sh"
fi
printf 'exit\n' >> "${ROOT}/root/init.sh"

# /etc/fstab
printf 'tmpfs          /tmp     tmpfs rw,nosuid,nodev,noatime                                                       0 0\n' > "${ROOT}/etc/fstab"
printf 'tmpfs          /dev/shm tmpfs rw,nosuid,noexec,nodev,noatime                                                0 0\n' >> "${ROOT}/etc/fstab"
printf '/dev/mmcblk0p1 /        ext4  ro,noatime,nodev,discard                                                      0 0\n' >> "${ROOT}/etc/fstab"
printf '/dev/mmcblk0p2 /var     btrfs rw,noatime,nodev,noexec,nosuid,compress=zstd,ssd,discard=async,subvol=/base   0 0\n' >> "${ROOT}/etc/fstab"

# SYSCONFIG Files
export ROOT
export SYSCONFIG
source "$(pwd)/config.sh"
if [ $? -ne 0 ]; then
    echo -e '\033[1;31mSourcing "\033[0mconfig.sh\033[1;31m" failed!\033[0m' 1>&2
    cleanup 1
fi

# Fixing permissions
chmod 444 "${ROOT}/etc/fstab"
chmod 500 "${ROOT}/root/init.sh"
chmod 400 "${ROOT}/boot/boot.txt"
chmod 444 "${ROOT}/boot/boot.scr"
chmod 444 "${ROOT}/etc/sysconfig.conf"
chmod 555 -R "${ROOT}${SYSCONFIG_DIR}/bin"

print "Preperaring to chroot into \"${ROOT}\"..."
exec "mount -o bind /dev ${ROOT}/dev"
exec "mount -o bind /sys ${ROOT}/sys"
exec "mount -o bind /proc ${ROOT}/proc"
exec "cp $(which qemu-arm-static) ${ROOT}/usr/bin/qemu-arm-static"
echo ':arm:M::\x7fELF\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x28\x00:\xff\xff\xff\xff\xff\xff\xff\x00\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xff\xff\xff:/usr/bin/qemu-arm-static:' > /proc/sys/fs/binfmt_misc/register 2> /dev/null

print "Running chroot init script..."
chroot "${ROOT}" "/root/init.sh"
[ $? -ne 0 ] && echo -e "\033[1;33mChroot non-zero exit code!\033[0m"

print "Chroot Done, cleaning up..."
rm "${ROOT}/root/init.sh" 2> /dev/null
rm "${ROOT}/root/extra.sh" 2> /dev/null
rm "${ROOT}/etc/resolv.conf" 2> /dev/null
rm "${ROOT}/etc/dnsmasq.conf.pacnew" 2> /dev/null
rm "${ROOT}/usr/bin/qemu-arm-static" 2> /dev/null
rm "${ROOT}/etc/systemd/network/eth0.network" 2> /dev/null

awk '$5 > 2000' "${ROOT}/etc/ssh/moduli" > "${ROOT}/etc/ssh/moduli"
printf 'nameserver 10.1.10.2\nsearch beagle.usb\n' > "${ROOT}/etc/resolv.conf"
chmod 400 "${ROOT}/etc/ssh/moduli"
chmod 444 "${ROOT}/etc/resolv.conf"
find "${ROOT}" -type f -name *.pacnew -delete

lsof -n | grep "$ROOT" | awk '{print $2}' | xargs kill -9
sleep 5
umount "${ROOT}/sys"
umount "${ROOT}/dev"
umount "${ROOT}/proc"
sync

print "Done!"
cleanup
