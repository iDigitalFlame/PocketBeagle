#!/usr/bin/bash
# Copyright 2021 - 2023 iDigitalFlame
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

if [ $UID -ne 0 ]; then
    echo "You MUST be root to do this!" 1>&2
    exit 1
fi

if [ $# -lt 3 ]; then
    printf "%s <tar image> <uboot dir> <disk> [source script]" "$0" 1>&2
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
    eval "$1" 1>/dev/null; r=$?
    if [ $# -eq 1 ]; then
        if [ $r -eq 0 ]; then
            return
        fi
        printf "\033[1;31mCommand \033[0m\"%s\"\033[1;31m exited witn a non-zero \033[0m(%d) \033[1;31mstatus code!\033[0m\n" "$1" "$r" 1>&2
        cleanup 1
    fi
    if [ $# -eq 3 ]; then
        if [ $r -eq "$2" ] || [ $r -eq "$3" ]; then
            return
        fi
        printf "\033[1;31mCommand \033[0m\"%s\"\033[1;31m exited witn a non-zero \033[0m(%d) \033[1;31mstatus code!\033[0m\n" "$1" "$r" 1>&2
        cleanup 1
    fi
    if [ "$r" -ne "$2" ]; then
        printf "\033[1;31mCommand \033[0m\"%s\"\033[1;31m exited with a \033[0m(%d) \033[1;31mstatus code!\033[0m\n" "$1" "$r" 1>&2
        cleanup 1
    fi
}
print() {
    printf "\033[1;32m"
    printf "%s" "$*"
    printf "\033[0m\n"
}
checks() {
    if ! which dd 1> /dev/null 2> /dev/null; then
        printf "\033[1;31m\033[0m\"dd\" \033[1;31mis missing, please install \033[0mcore\"utils\" \033[1;31mfirst!\033[0m\n" 1>&2
        exit 1
    fi
    if ! which lsof 1> /dev/null 2> /dev/null; then
        printf "\033[1;31m\033[0m\"lsof\" \033[1;31mis missing, please install \033[0m\"lsof\" \033[1;31mfirst!\033[0m\n" 1>&2
        exit 1
    fi
    if ! which bsdtar 1> /dev/null 2> /dev/null; then
        printf "\033[1;31m\033[0m\"bsdtar\" \033[1;31mis missing, please install \033[0m\" libarchive\" \033[1;31mfirst!\033[0m\n" 1>&2
        exit 1
    fi
    if ! which mkimage 1> /dev/null 2> /dev/null; then
        printf "\033[1;31m\033[0m\"mkimage\" \033[1;31mis missing, please install \033[0m\"uboot-tools\" \033[1;31mfirst!\033[0m\n" 1>&2
        exit 1
    fi
    if ! which mkfs.ext4 1> /dev/null 2> /dev/null; then
        printf "\033[1;31m\033[0\"mmkfs.ext4\" \033[1;31mis missing, please install \033[0m\"e2fsprogs\" \033[1;31mfirst!\033[0m\n" 1>&2
        exit 1
    fi
    if ! which mkfs.vfat 1> /dev/null 2> /dev/null; then
        printf "\033[1;31m\033[0m\"mkfs.vfat\" 033[1;31mis missing, please install \033[0m\"dosfstools\" \033[1;31mfirst!\033[0m\n" 1>&2
        exit 1
    fi
    if ! which mkfs.btrfs 1> /dev/null 2> /dev/null; then
        printf "\033[1;31m\033[0m\"mkfs.btrfs\" 033[1;31mis missing, please install \033[0m\"btrfs-progs\" \033[1;31mfirst!\033[0m\n" 1>&2
        exit 1
    fi
    if ! which qemu-arm-static 1> /dev/null 2> /dev/null; then
        printf "\033[1;31m\033[0m\"qemu-arm-static\" \033[1;31mis missing, please install 033[0m\"qemu-user-static\" \033[1;31mfirst!\033[0m\n" 1>&2
        exit 1
    fi
    if ! [ -b "$DISK" ]; then
        printf "\033[1;31mPath \033[0m\"%s\" \033[1;31mis not a block device!\033[0m\n" "$DISK" 1>&2
        exit 1
    fi
    if ! [ -f "$IMAGE" ]; then
        printf "\033[1;31mImage path \033[0m\"%s\" \033[1;31mdoes not exist!\033[0m\n" "$IMAGE" 1>&2
        exit 1
    fi
    if ! [ -d "${UBOOT}" ]; then
        printf "\033[1;31mUboot path \033[0m\"%s\" \033[1;31mis not a directory!\033[0m\n" "$UBOOT" 1>&2
        exit 1
    fi
    if ! [ -f "${UBOOT}/MLO" ]; then
        printf "\033[1;31mUboot path \033[0m\"%s/MLO\" \033[1;31mdoes not exist!\033[0m\n" "$UBOOT" 1>&2
        exit 1
    fi
    if ! [ -f "${UBOOT}/u-boot.img" ]; then
        printf "\033[1;31mUboot path \033[0m\"%s/u-boot.img\" \033[1;31mdoes not exist!\033[0m\n" "$UBOOT" 1>&2
        exit 1
    fi
    if ! [ -f "$(pwd)/config.sh" ]; then
        printf "\033[1;31mPath 033[0m\"%s/config.sh\" \033[1;31mdoes not exist!\033[0m\n" "$(pwd)" 1>&2
        exit 1
    fi
}
cleanup() {
    print "Performing cleanup..."
    sync
    umount "/proc/sys/fs/binfmt_misc" 2> /dev/null
    umount "${ROOT}/var" 2> /dev/null
    umount "${ROOT}" 2> /dev/null
    rmdir "${ROOT}" 2> /dev/null
    if [ $# -ne 1 ]; then
        exit 0
    fi
    exit "$1"
}

# Check env first
checks

# Set Cleanup on failure
trap cleanup 1 2 3 6

print "Zero-ing out the UBoot sectors.."
exec "dd if=/dev/zero of=${DISK} bs=1M count=8"

total=$(fdisk -l "${DISK}" | grep "Disk" | grep "sectors" | awk '{print $7}')
if [ $? -ne 0 ]; then
    printf "\033[1;31Could not get disk sector size!\033[0m\n" 1>&2
    cleanup 1
fi

size_root=$((total - 16781312))
size_cache=$((size_root + 16777217))

print "Partitioning disk ${DISK}.."
printf "o\nn\np\n1\n4096\n%d\ny\nn\np\n2\n%d\n%d\ny\nw\n" "$size_root" "$((size_root + 1))" "$size_cache" | exec "fdisk ${DISK}"

print "Creating and formatting partitions.."
exec "mkfs.ext4 -q -L root -F ${DISK}p1"
exec "mkfs.btrfs -L cache -f ${DISK}p2"

print "Mounting partitions.."
exec "mkdir -p ${ROOT}"
exec "mount -t ext4 -o rw,noatime,nodev,discard ${DISK}p1 ${ROOT}"
exec "mkdir -p ${ROOT}/var"
exec "mount -t btrfs -o rw,noatime,nodev,noexec,nosuid,space_cache=v2,compress=zstd,ssd,discard=async ${DISK}p2 ${ROOT}/var"
exec "btrfs subvolume create ${ROOT}/var/base"
exec "umount ${ROOT}/var"
exec "mount -t btrfs -o rw,noatime,nodev,noexec,nosuid,space_cache=v2,compress=zstd,ssd,discard=async,subvol=/base ${DISK}p2 ${ROOT}/var"

print "Extracting ${IMAGE} to disk..."
exec "bsdtar -xpf \"${IMAGE}\" -C ${ROOT}"
sync

print "Copying and Installing Uboot.."
rm -f "${ROOT}/boot/MLO" 2> /dev/null
rm -f "${ROOT}/boot/boot.txt" 2> /dev/null
rm -f "${ROOT}/boot/boot.scr" 2> /dev/null
rm -f "${ROOT}/boot/u-boot.img" 2> /dev/null
exec "cp \"${UBOOT}/MLO\" ${ROOT}/boot/MLO"
exec "cp \"${UBOOT}/u-boot.img\" ${ROOT}/boot/u-boot.img"
exec "dd if=${ROOT}/boot/MLO of=${DISK} count=1 seek=1 conv=notrunc bs=128k"
exec "dd if=${ROOT}/boot/u-boot.img of=${DISK} count=2 seek=1 conv=notrunc bs=384k"
sync

mac_addr=$(printf '%x%x:%x%x:%x%x' $((RANDOM % 10)) $((RANDOM % 10)) $((RANDOM % 10)) $((RANDOM % 10)) $((RANDOM % 10)) $((RANDOM % 10)))
printf 'if test -n ${distro_bootpart}; then setenv bootpart ${distro_bootpart}; ' > "${ROOT}/boot/boot.txt"
printf 'else setenv bootpart 1; fi\npart uuid ${devtype} ${devnum}:${bootpart} uuid\n\n' >> "${ROOT}/boot/boot.txt"
printf 'setenv bootargs "console=tty0 console=${console} root=PARTUUID=${uuid} rootwait' >> "${ROOT}/boot/boot.txt"
printf ' ro quiet loglevel=2 audit=0 rd.systemd.show_status=auto rd.udev.log_priority=2 modules-load=dwc2,g_ether ' >> "${ROOT}/boot/boot.txt"
printf "ipv6.disable=1 g_ether.host_addr=be:ef:ed:${mac_addr} g_ether.dev_addr=${mac_addr}\"" >> "${ROOT}/boot/boot.txt"
printf '\n\nif load ${devtype} ${devnum}:${bootpart} ${kernel_addr_r} /boot/zImage; then\n  gpio set 54\n' >> "${ROOT}/boot/boot.txt"
printf '  echo fdt: ${fdtfile}\n  if load ${devtype} ${devnum}:${bootpart} ${fdt_addr_r} /boot/dtbs/${fdtfile};' >> "${ROOT}/boot/boot.txt"
printf ' then\n    gpio set 55\n    if load ${devtype} ${devnum}:${bootpart} ${ramdisk_addr_r} ' >> "${ROOT}/boot/boot.txt"
printf '/boot/initramfs-linux.img; then\n      gpio set 56\n      bootz ${kernel_addr_r}' >> "${ROOT}/boot/boot.txt"
printf ' ${ramdisk_addr_r}:${filesize} ${fdt_addr_r};\n    else\n      gpio set 56\n' >> "${ROOT}/boot/boot.txt"
printf '      bootz ${kernel_addr_r} - ${fdt_addr_r};\n    fi;\n  fi;\nfi\n' >> "${ROOT}/boot/boot.txt"
exec "mkimage -A arm -O linux -T script -C none -n 'U-Boot boot script' -d ${ROOT}/boot/boot.txt ${ROOT}/boot/boot.scr"

print "Preparing supplimantary files.."
# Fix DNS Config issue
rm "${ROOT}/etc/resolv.conf"
cp -fL "/etc/resolv.conf" "${ROOT}/etc/resolv.conf"

# /etc/sysconfig.conf
printf "SYSCONFIG=%s\n" "$SYSCONFIG_DIR" > "${ROOT}/etc/sysconfig.conf"

# /root/init.sh
printf '#!/usr/bin/bash\n\n' > "${ROOT}/root/init.sh"
printf "bash %s/bin/relink %s /\n" "$SYSCONFIG_DIR" "$SYSCONFIG_DIR" >> "${ROOT}/root/init.sh"
printf "bash %s/bin/syslink\n" "$SYSCONFIG_DIR" >> "${ROOT}/root/init.sh"
printf 'locale-gen\n' >> "${ROOT}/root/init.sh"
printf 'pacman-key --init\n' >> "${ROOT}/root/init.sh"
printf 'pacman-key --populate archlinuxarm\n' >> "${ROOT}/root/init.sh"
printf 'pacman -Syy --noconfirm\n' >> "${ROOT}/root/init.sh"
printf 'pacman -Syu --noconfirm\n' >> "${ROOT}/root/init.sh"
printf 'pacman -S dnsmasq btrfs-progs pacman-contrib zstd --noconfirm\n' >> "${ROOT}/root/init.sh"
printf 'mount -o rw,remount /\n' >> "${ROOT}/root/init.sh"
printf 'systemctl mask debug-shell.service > /dev/null\n' >> "${ROOT}/root/init.sh"
printf 'systemctl mask display-manager.service > /dev/null\n' >> "${ROOT}/root/init.sh"
printf 'systemctl mask plymouth-quit-wait.service > /dev/null\n' >> "${ROOT}/root/init.sh"
printf 'systemctl mask plymouth-start.service > /dev/null\n' >> "${ROOT}/root/init.sh"
printf 'systemctl mask syslog.service > /dev/null\n' >> "${ROOT}/root/init.sh"
printf 'systemctl mask syslog.target > /dev/null\n' >> "${ROOT}/root/init.sh"
printf 'systemctl mask rescue.service > /dev/null\n' >> "${ROOT}/root/init.sh"
printf 'systemctl mask emergency.service > /dev/null\n' >> "${ROOT}/root/init.sh"
printf 'systemctl mask emergency.target > /dev/null\n' >> "${ROOT}/root/init.sh"
printf 'systemctl mask var-lib-machines.mount > /dev/null\n' >> "${ROOT}/root/init.sh"
printf 'systemctl mask systemd-boot-system-token.service > /dev/null\n' >> "${ROOT}/root/init.sh"
printf 'systemctl mask systemd-firstboot.service > /dev/null\n' >> "${ROOT}/root/init.sh"
printf 'systemctl mask systemd-homed.service > /dev/null\n' >> "${ROOT}/root/init.sh"
printf 'systemctl mask systemd-hwdb-update.service > /dev/null\n' >> "${ROOT}/root/init.sh"
printf 'systemctl mask systemd-network-generator.service > /dev/null\n' >> "${ROOT}/root/init.sh"
printf 'systemctl mask systemd-pstore.service > /dev/null\n' >> "${ROOT}/root/init.sh"
printf 'systemctl mask systemd-repart.service > /dev/null\n' >> "${ROOT}/root/init.sh"
printf 'systemctl mask systemd-sysusers.service > /dev/null\n' >> "${ROOT}/root/init.sh"
printf 'systemctl mask first-boot-complete.target > /dev/null\n' >> "${ROOT}/root/init.sh"
printf 'systemctl disable systemd-resolved > /dev/null\n' >> "${ROOT}/root/init.sh"
printf 'rm /etc/systemd/system/multi-user.target.wants/systemd-resolved.service 2> /dev/null\n' >> "${ROOT}/root/init.sh"
printf 'rm /etc/systemd/system/dbus-org.freedesktop.resolve1.service 2> /dev/null\n' >> "${ROOT}/root/init.sh"
printf 'systemctl enable systemd-networkd.service > /dev/null\n' >> "${ROOT}/root/init.sh"
printf 'systemctl enable systemd-timesyncd.service > /dev/null\n' >> "${ROOT}/root/init.sh"
printf 'systemctl enable dnsmasq.service > /dev/null\n' >> "${ROOT}/root/init.sh"
printf 'systemctl enable fstrim.timer > /dev/null\n' >> "${ROOT}/root/init.sh"
printf 'pacman -Rsc $(pacman -Qtdq) --noconfirm 2> /dev/null\n' >> "${ROOT}/root/init.sh"
printf 'mount -o rw,remount /\n' >> "${ROOT}/root/init.sh"
printf 'ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N "" < /dev/null > /dev/null\n' >> "${ROOT}/root/init.sh"
printf 'ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N "" < /dev/null > /dev/null\n' >> "${ROOT}/root/init.sh"
printf 'ssh-keygen -A\n' >> "${ROOT}/root/init.sh"
printf 'chmod 400 /etc/ssh/*_key\n' >> "${ROOT}/root/init.sh"
printf 'userdel -rf alarm 2> /dev/null\n' >> "${ROOT}/root/init.sh"

if [ -n "$SCRIPT" ] && [ -f "$SCRIPT" ]; then
    print "Addding addditional script \"${SCRIPT}\".."
    cp "$SCRIPT" "${ROOT}/root/extra.sh"
    chmod 500 "${ROOT}/root/extra.sh"
    printf 'bash /root/extra.sh\n' >> "${ROOT}/root/init.sh"
fi

printf 'exit\n' >> "${ROOT}/root/init.sh"

# /etc/fstab
printf 'tmpfs          /tmp     tmpfs rw,noatime,nodev,nosuid                                                                       0 0\n' > "${ROOT}/etc/fstab"
printf 'tmpfs          /dev/shm tmpfs rw,noatime,nodev,noexec,nosuid                                                                0 0\n' >> "${ROOT}/etc/fstab"
printf '/dev/mmcblk0p1 /        ext4  ro,noatime,nodev,discard                                                                      0 1\n' >> "${ROOT}/etc/fstab"
printf '/dev/mmcblk0p2 /var     btrfs rw,noatime,nodev,noexec,nosuid,space_cache=v2,compress=zstd,ssd,discard=async,subvol=/base    0 0\n' >> "${ROOT}/etc/fstab"

# SYSCONFIG Files
export ROOT
export SYSCONFIG
if ! source "$(pwd)/config.sh"; then
    printf "\033[1;31mSourcing \033[0m\"config.sh\" \033[1;31mfailed!\033[0m\n" 1>&2
    cleanup 1
fi

# Fixing permissions
chmod 0444 "${ROOT}/etc/fstab"
chmod 0500 "${ROOT}/root/init.sh"
chmod 0400 "${ROOT}/boot/boot.txt"
chmod 0444 "${ROOT}/boot/boot.scr"
chmod 0444 "${ROOT}/etc/sysconfig.conf"
chmod 0555 -R "${ROOT}${SYSCONFIG_DIR}/bin"

print "Preperaring to chroot into \"${ROOT}\".."
exec "mount -o bind /dev ${ROOT}/dev"
exec "mount -o bind /sys ${ROOT}/sys"
exec "mount -o bind /proc ${ROOT}/proc"
exec "cp $(which qemu-arm-static) ${ROOT}/usr/bin/qemu-arm-static"
printf ':arm:M::\x7fELF\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x28\x00:\xff\xff\xff\xff\xff\xff\xff\x00\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xff\xff\xff:/usr/bin/qemu-arm-static:\n' > /proc/sys/fs/binfmt_misc/register 2> /dev/null

print "Running chroot init script.."
if ! chroot "${ROOT}" "/root/init.sh"; then
    printf "\033[1;33mChroot non-zero exit code!\033[0m\n"
fi

mount -o rw,remount "${ROOT}"

print "Chroot Done, cleaning up.."
rm "${ROOT}/root/init.sh" 2> /dev/null
rm "${ROOT}/root/extra.sh" 2> /dev/null
rm "${ROOT}/etc/resolv.conf" 2> /dev/null
rm "${ROOT}/etc/dnsmasq.conf.pacnew" 2> /dev/null
rm "${ROOT}/usr/bin/qemu-arm-static" 2> /dev/null
rm "${ROOT}/etc/systemd/network/eth0.network" 2> /dev/null

awk '$5 > 2000' "${ROOT}/etc/ssh/moduli" > "${ROOT}/etc/ssh/moduli"
printf 'nameserver 10.1.10.2\nsearch beagle.usb\n' > "${ROOT}/etc/resolv.conf"
chmod 0400 "${ROOT}/etc/ssh/moduli"
chmod 0444 "${ROOT}/etc/resolv.conf"
find "${ROOT}" -type f -name "*.pacnew" -delete 2> /dev/null

lsof -n | grep "$ROOT" | awk '{print $2}' | xargs kill -9
sleep 5
umount "${ROOT}/sys"
umount "${ROOT}/dev"
umount "${ROOT}/proc"
sync

printf "\033[1;32mPlease change the \033[0mroot\033[1;32m user password on first login!!\033[0m\n"
print "Done!"
cleanup
