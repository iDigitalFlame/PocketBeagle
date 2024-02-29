#!/usr/bin/bash

ln -sT "/etc/sysless" "/etc/syslesskey" 2> /dev/null
ln -sT "/etc/sysless" "/usr/local/etc/syslesskey" 2> /dev/null

chmod 0444 "/etc/sysless"
chmod 0444 "/etc/syslesskey"
chmod 0444 "/usr/local/etc/syslesskey"
