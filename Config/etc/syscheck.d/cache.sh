#!/usr/bin/bash

rm "/etc/.updated" 2> /dev/null
rm "/etc/.pwd.lock" 2> /dev/null

if ! readlink "/etc/ld.so.cache" 2> /dev/null 1> /dev/null; then
    mv "/etc/ld.so.cache" "/var/cache/ld.so.cache"
fi
if ! readlink "/etc/pacman.d/gnupg" 2> /dev/null 1> /dev/null; then
    mkdir -p "/var/db/pacman"
    mv "/etc/pacman.d/gnupg" "/var/db/pacman/gnupg"
fi
if ! readlink "/etc/pacman.d/mirrorlist" 2> /dev/null 1> /dev/null; then
    mv "/etc/pacman.d/mirrorlist" "/var/cache/pacman/mirrorlist"
fi

rm -f "/etc/ld.so.cache"
rm -f "/etc/pacman.d/gnupg"
rm -f "/etc/pacman.d/mirrorlist"

if ! [ -e "/var/cache/ld.so.cache" ]; then
    touch "/var/cache/ld.so.cache" 2> /dev/null
fi

ln -sT "/var/cache/ld.so.cache" "/etc/ld.so.cache"
ln -sT "/var/db/pacman/gnupg" "/etc/pacman.d/gnupg"
ln -sT "/var/cache/pacman/mirrorlist" "/etc/pacman.d/mirrorlist"

chmod 0644 "/var/cache/ld.so.cache"
chown root:root "/var/cache/ld.so.cache"

chmod -R 0750 "/var/cache/pacman/pkg"
chmod 0640 /var/cache/pacman/pkg/*
chown -R root:root "/var/cache/pacman/pkg"

chmod 0755 "/var/lib/pacman/sync"
chmod 0644 /var/lib/pacman/sync/*
chown -R root:root "/var/lib/pacman/sync"

chmod -R 0755 "/var/lib/pacman/local"
chown -R root:root "/var/lib/pacman/local"
find "/var/lib/pacman" -type f -exec chmod 0644 {} \;

chmod 0700 "/var/cache/ldconfig"
chown -R root:root "/var/cache/ldconfig"
