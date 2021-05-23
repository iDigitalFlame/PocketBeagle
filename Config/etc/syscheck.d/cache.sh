#!/usr/bin/bash

rm "/etc/.updated" 2> /dev/null
rm "/etc/.pwd.lock" 2> /dev/null
rm "/etc/ld.so.cache" 2> /dev/null

if ! [ -e "/var/cache/ld.so.cache" ]; then
    touch "/var/cache/ld.so.cache" 2> /dev/null
fi
ln -s "/var/cache/ld.so.cache" "/etc/ld.so.cache" 2> /dev/null

chmod 0644 "/var/cache/ld.so.cache"
chown root:root "/var/cache/ld.so.cache"
