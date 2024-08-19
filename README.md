# PocketBeagle Builder

This repo is dedicated to my build, install and configuration scripts for the
[PocketBeagle](https://beagleboard.org/pocket).

You can use the `install.sh` script to install and configure an ArchLinux install
that contains:

- USB Gadget (Ethernet) Support
- Auto DHCP
- Support to local proxy via Squid
- Read-only Root
- BTRFS Cache partition
- Local Console via UART

The install script requires a valid ArchLinux tar blob, which can be downloaded
[here](http://os.archlinuxarm.org/os/ArchLinuxARM-am33x-latest.tar.gz) or by
issuing the command:

- `wget http://os.archlinuxarm.org/os/ArchLinuxARM-am33x-latest.tar.gz`
- or
- `curl -Lo ArchLinuxARM-am33x-latest.tar.gz http://os.archlinuxarm.org/os/ArchLinuxARM-am33x-latest.tar.gz`

The `UbootRepo` directory is a modified Uboot build by @NitroProp
[https://github.com/NitroProp/PocketBeagle-ARCH-ReARMed](https://github.com/NitroProp/PocketBeagle-ARCH-ReARMed)
(thanks!) that is used for booting. (duh).

## Command Line Arguments

`sudo bash install.sh <tar> <uboot_dir> <disk> [source script]`

An example that should work "Out-Of-The-Box" would be:

```shell
sudo bash install.sh ArchLinuxARM-am33x-latest.tar.gz ./UbootRepo/u-boot /dev/mmcblk0
```

This example assumes the SD card you'd be using is at `/dev/mmcblk0`.

The last command line argument `[source script]` is a path to a script file that
is executed in the **Context of the Beagle (ARM) before completion** which allows
you to install other programs, enable systemd units, etc. This optional argument
is ignored if the path suggested does not exist, or is not a file.

## Install Requirements

(on the computer you're using to install from):

- `qemu-arm-static` from "qemu-user-static" (ARM chroot)
- `dd` from "coreutils" (Writing to the SD card)
- `lsof` from "lsof" (Process monitoring)
- `bsdtar` from "libarchive" (Extraction)
- `mkfs.ext4` from "e2fsprogs" (Formatting)
- `mkfs.vfat` from "dosfstools" (Formatting)
- `mkfs.btrfs` from "btrfs-progs" (Formatting)

## Building "config.sh"

The contents of "Config" directory are built using the `build-config.py` file with
the arguments:

```shell
python build-config.py ./Config ./config.sh
```

This will generate the configuration script from any changes made in the `Config`
folder. *(Requires `python3`)*

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/Z8Z4121TDS)
