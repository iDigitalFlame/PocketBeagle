#!/usr/bin/bash

__status_repo() {
    if ! source "/etc/sysconfig.conf" 2> /dev/null; then
        return 0
    fi
    if [ -z "$SYSCONFIG" ]; then
        return 0
    fi
    if ! [ -d "$SYSCONFIG" ]; then
        return 0
    fi
    SYSCONFIG=${SYSCONFIG%/}
    if ! [ -d "${SYSCONFIG}/.git" ]; then
        return 0
    fi
    if sh -c "cd ${SYSCONFIG}; git status | grep -qiE 'modified|deleted|Untracked'"; then
        printf '# Config:\tSync needed, use "syspush"\n'
    else
        printf "# Config:\tUp-to-Date\n"
    fi
}
__status_storage() {
    echo "# Storage:"
    df -h | grep -v "tmpfs" | grep -E '/dev/|/opt/|/mnt/' | sort -r | awk '{print ""$1" "$5" ("$3"/"$2")"}' | sort | column -t | awk '{print "#     "$0}'
}
__status_network() {
    echo "# Interface Addresses:"
    for i in $(ip addr | grep "inet" | grep -vE "::1|127.0.0.1|link" | awk '{print $2}' | awk -F'/' '{print $1}'); do
        printf "#     %s\n" "$i"
    done
}
__status_services() {
    printf "# Network:\t%s Established, " "$(netstat -panut 2> /dev/null | grep -c "ESTABLISHED")"
    printf "%s Listening\n" "$(netstat -panut 2> /dev/null | grep -c "LISTEN")"
    printf "# Services:\t%s Running, " "$(systemctl --state=active --no-legend --no-pager | grep ".service" | grep -c "running")"
    printf "%s Failed, " "$(systemctl --state=failed --no-legend --no-pager | grep -c ".service")"
    printf "%s Timers\n" "$(systemctl --all --no-legend --no-pager | grep -c ".timer")"
}

if [[ $- != *i* ]] || [ -n "$SSH_CLIENT" ]; then
    printf "##############################################################\n"
    __status_storage
    __status_network
    printf "# Uptime:\t%s\n" "$(uptime --pretty | sed 's/up //g')"
    printf "# Kernel:\t%s\n" "$(uname -r)"
    __status_repo
    __status_services
    printf "##############################################################\n"
fi
