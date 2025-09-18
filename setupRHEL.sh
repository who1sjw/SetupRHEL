#!/bin/bash
# This script standardizes configuration for freshly installed RHEL7/CentOS7 systems.
# Use with caution on systems that have already been configured.
# Some settings may require a reboot to take effect.
# To run non-interactively, pass the argument 'yes'.
# version: 0.1
# jingw.nz@gmail.com
#
# --- OVERVIEW ---
# This script applies opinionated baseline settings for RHEL/CentOS 7 servers:
# - Creates an admin user and grants passwordless sudo
# - Tunes security (SSH, PAM, password policy, faillock)
# - Sets timezone/NTP, logrotate, rsyslog, system limits, sysctl
# - Manages services, SELinux, runlevel, USB storage, Ctrl-Alt-Del
# - Optionally configures YUM repos, auditd rules, and kernel crashkernel

# Confirm you understand the impact before running in production.
# --- CHANGE/REBOOT MARKERS (for Ansible idempotency) ---
CHANGE_MARK="/var/run/setupRHEL.changed"
REBOOT_MARK="/var/run/setupRHEL.reboot"
CHANGED=0
REBOOT=0
mark_changed() { CHANGED=1; }
mark_reboot()  { REBOOT=1; }


 # create_user: Create the primary admin group/user with specific IDs, set password, and remove default 'osinstall' if present.
create_user() {
    if ! getent group $group >/dev/null; then
        groupadd -g $groupid $group
        mark_changed
        echo "Created group '$group'"
    fi
    if ! id $user >/dev/null 2>&1; then
        useradd -u $userid -g $group -s /bin/bash $user
        echo "$user:$password" |chpasswd
        echo "Created user '$user' in group '$group'"
        mark_changed
	userdel -r osinstall
        mark_changed
        # passwd -e $user >/dev/null 2>&1
        # echo "Set password must be changed at the next login for '$user'"
    fi
}

 # set_sudo: Grant passwordless sudo (NOPASSWD) to the configured admin user in /etc/sudoers.
set_sudo() {
    local file='/etc/sudoers'
    if ! egrep -q "^\s*$user\s+ALL=\(ALL\)\s+NOPASSWD:\s+ALL" $file; then
        echo "$user ALL=(ALL) NOPASSWD: ALL" >> $file; mark_changed
        echo "Set '$user ALL=(ALL) NOPASSWD: ALL' in $file"; mark_changed
    fi
}

 # set_fstab: Ensure mount options (e.g., nosuid/noexec) are present for specific paths in /etc/fstab.
set_fstab() {
    local file='/etc/fstab'
    while read line; do
        changed=()
        item=` awk '{print $1}' <<< "$line" `
        value=` awk '{print $2}' <<< "$line" `
        if egrep -q "^[^#]*\s+$item\s+" $file ; then
            for v in ${value//,/ }; do
                if ! egrep -q "^[^#]*\s+$item\s+.*$v" $file; then
                    sed -ri "s@(^[^#]*\s+$item\s+.*defaults)(.*)@\1,$v\2@" $file
                    changed+=($v)
                fi
            done
        fi

        if [ ${#changed[@]} -gt 0 ]; then
            echo "Set '$item $(echo ${changed[@]} | sed 's/\s/,/g')' in $file"
        fi
    done <<< "$etc_fstab"
}

 # disable_selinux: Set SELINUX mode in /etc/selinux/config (may require reboot).
disable_selinux() {
    local file='/etc/selinux/config'
    if ! grep -q "^\s*SELINUX=$selinux" $file; then
         sed -i "s/^\s*SELINUX=.*/SELINUX=$selinux/" $file
         echo "Set 'SELINUX=$selinux' in $file"; mark_changed; mark_reboot
         
    fi
}

 # set_runlevel: Set the default systemd target (e.g., multi-user.target).
set_runlevel() {
    if [ $(systemctl get-default) != "$runlevel" ]; then
        systemctl set-default $runlevel > /dev/null 2>&1
        echo "Set runlevel '$runlevel'"; mark_changed; mark_reboot
    fi
}

 # grub2_mkconfig: Regenerate GRUB2 configuration for BIOS/UEFI as appropriate.
grub2_mkconfig() {
    if [ -d /sys/firmware/efi ]; then
        local file='/boot/efi/EFI/redhat/grub.cfg'
    else
        local file='/boot/grub2/grub.cfg'
    fi
    grub2-mkconfig -o $file > /dev/null 2>&1
    echo "Maked grub2 config to $file"
}

 # disable_ipv6: Append ipv6.disable=1 to GRUB kernel args and regenerate GRUB (requires reboot).
disable_ipv6() {
    # if grep -q "ipv6.disable=1" /proc/cmdline; then
    #     return
    # fi
    local file='/etc/default/grub'
    if ! grep -q '^GRUB_CMDLINE_LINUX=.*ipv6.disable=1.*' $file; then
        sed -ri 's/(^GRUB_CMDLINE_LINUX=".*)"/\1 ipv6.disable=1"/' $file
        echo "Set 'ipv6.disable=1' in $file"; mark_changed; mark_reboot
        grub2_mkconfig
    fi
}

 # set_timezone: Configure system timezone via timedatectl.
set_timezone() {
    if ! timedatectl status |grep 'Time zone' |grep -q "$timezone"; then
        timedatectl set-timezone $timezone
        echo "Set timezone '$timezone'"; mark_changed
    fi
}

 # set_chrony: Replace chrony NTP sources with the provided list and restart chronyd.
set_chrony() {
    local file="/etc/chrony.conf"
    s1=$(egrep -o "^\s*server\s+([^#]+)" $file | sed 's/\s*$//' | sort -n | tr '\n' ',' | sed 's/,$//')
    s2=$(echo "$chrony_sources" | sort -n | tr '\n' ',' | sed 's/,$//')
    if [ "$s1" != "$s2" ]; then
        sed -ri '/^\s*pool\s+/d' $file
        sed -ri '/^\s*server\s+/d' $file
        echo "$chrony_sources" >> $file
        systemctl restart chronyd > /dev/null 2>&1
        echo "Set '$chrony_sources' in $file"; mark_changed
    fi
}

 # enable_kdump: Enable kernel crashkernel=auto via GRUB (requires reboot to take effect).
enable_kdump() {
    # if grep -qw 'crashkernel' /proc/cmdline; then
    # If crashkernel is already set in the current kernel cmdline, skip.
    #     return
    # fi
    local file='/etc/default/grub'
    if ! grep -q '^\s*GRUB_CMDLINE_LINUX.*crashkernel' $file ; then
        sed -ri 's/(^GRUB_CMDLINE_LINUX=".*)"/\1 crashkernel=auto"/' $file
        echo "Set 'crashkernel=auto' in $file"; mark_changed; mark_reboot
        grub2_mkconfig
    fi
}

 # set_cron_user: Restrict cron to root and the admin user via /etc/cron.allow.
set_cron_user() {
    local file='/etc/cron.allow'
    if [ ! -f $file ]; then
        echo -e "root\n$user" > $file
        mark_changed
        chmod 600 $file
        echo "Set 'root, $user' in $file"
    fi
}

 # set_cron_mail: Disable cron mail notifications by setting MAILTO="" in /etc/crontab.
set_cron_mail() {
    local file='/etc/crontab'
    if ! grep -q -e ^MAILTO=\"\" -e ^MAILTO=\'\' $file; then
        sed -i 's/^MAILTO=.*/MAILTO=""/' $file
        echo "Set 'MAILTO=\"\"' in $file"; mark_changed
    fi
}

 # set_service: Enable/start desired services and disable/stop undesired ones via systemd.
set_service() {
    for s in $services_on; do
        if systemctl list-unit-files |grep -q -w $s; then
            if ! systemctl is-enabled $s >/dev/null 2>&1; then
                systemctl enable $s >/dev/null 2>&1
                echo "Enabled service '$s'"; mark_changed
            fi
            if ! systemctl is-active $s >/dev/null 2>&1; then
                systemctl start $s >/dev/null 2>&1
                echo "Started service '$s'"; mark_changed
            fi
        fi
    done

    for s in $services_off; do
        if systemctl list-unit-files |grep -q -w $s; then
            if systemctl is-enabled $s >/dev/null 2>&1; then
                systemctl disable $s >/dev/null 2>&1
                echo "Disabled service '$s'"; mark_changed
            fi
            if systemctl is-active $s >/dev/null 2>&1; then
                systemctl stop $s >/dev/null 2>&1
                echo "Stopped service '$s'"; mark_changed
            fi
        fi
    done
}

 # set_ulimit: Configure file descriptor and process limits in limits.conf and neutralize conflicting 20-nproc.conf entries.
set_ulimit() {
    local file="/etc/security/limits.conf"
    local file_nproc="/etc/security/limits.d/20-nproc.conf"
    while read line; do
        domain=` awk '{print $1}' <<< "$line" `
        type=` awk '{print $2}' <<< "$line" `
        item=` awk '{print $3}' <<< "$line" `
        value=` awk '{print $4}' <<< "$line" `

        if [ $"$domain" == "*" ]; then
            if ! egrep -q "^\s*\*\s+$type\s+$item\s+$value\b" $file; then
                sed -ri "/^\s*\*\s+$type\s+$item\s+/d" $file
                echo "$line" >> $file
                echo "Set '$line' in $file"
            fi
            if [ -s $file_nproc ]; then
                if egrep -q "^\s*\*\s+$type\s+$item\s+" $file_nproc; then
                    echo "Commented '` egrep "^\s*\*\s+$type\s+$item\s+" $file_nproc `' in $file_nproc"
                    sed -ri "s/(^\s*\*\s+$type\s+$item\s+.*)/#\1/" $file_nproc
                fi
            fi
        else
            if ! egrep -q "^\s*$domain\s+$type\s+$item\s+$value\b" $file; then
                sed -ri "/^\s*$domain\s+$type\s+$item\s+/d" $file
                echo "$line" >> $file
                echo "Set '$line' in $file"
            fi
            if [ ! -s $file_nproc ]; then continue; fi
            if egrep -q "^\s*$domain\s+$type\s+$item\s+" $file_nproc; then
                echo "Commented '` egrep "^\s*$domain\s+$type\s+$item\s+" $file_nproc `' in $file_nproc"
                sed -ri "s/(^\s*$domain\s+$type\s+$item\s+.*)/#\1/" $file_nproc
            fi
        fi
    done <<< "$ulimit"
}

 # set_sysctl: Enforce kernel/network tunables in /etc/sysctl.conf and apply with sysctl -p.
set_sysctl() {
    local file='/etc/sysctl.conf'
    while read line; do
        item="${line% =*}"
        value="${line#*= }"
        if ! grep -qw "^\s*$item" $file; then
            echo "$line" >> $file
            echo "Set '$line' in $file"; mark_changed
        else
            v=` sed -rn "s/^\s*$item[ =]+//p" /etc/sysctl.conf `
            if [ "$value" != "$v" ]; then
                sed -ri "s/(^\s*$item[ =]+).*/\1$value/" $file
                echo "Set '$line' in $file"; mark_changed
            fi
        fi
    done <<< "$sysctl"
    sysctl -p > /dev/null
}

 # set_password_age: Set password aging defaults (PASS_MAX_DAYS, PASS_MIN_DAYS, etc.) in /etc/login.defs.
set_password_age() {
    local file='/etc/login.defs'
    _pass_max_days=$(awk '/^PASS_MAX_DAYS/ {print $2}' $file)
    if [ $_pass_max_days -ne $pass_max_days ]; then
        sed -ri "s/(^PASS_MAX_DAYS\s+).*/\1$pass_max_days/" $file
        echo "Set 'PASS_MAX_DAYS $pass_max_days' in $file"
    fi
    _pass_min_days=$(awk '/^PASS_MIN_DAYS/ {print $2}' $file)
    if [ $_pass_min_days -ne $pass_min_days ]; then
        sed -ri "s/(^PASS_MIN_DAYS\s+).*/\1$pass_min_days/" $file
        echo "Set 'PASS_MIN_DAYS $pass_min_days' in $file"
    fi
    _pass_min_len=$(awk '/^PASS_MIN_LEN/ {print $2}' $file)
    if [ $_pass_min_len -ne $pass_min_len ]; then
        sed -ri "s/(^PASS_MIN_LEN\s+).*/\1$pass_min_len/" $file
        echo "Set 'PASS_MIN_LEN $pass_min_len' in $file"
    fi
    _pass_warn_days=$(awk '/^PASS_WARN_AGE/ {print $2}' $file)
    if [ $_pass_warn_days -ne $pass_warn_days ]; then
        sed -ri "s/(^PASS_WARN_AGE\s+).*/\1$pass_warn_days/" $file
        echo "Set 'PASS_WARN_AGE $pass_warn_days' in $file"
    fi
    
    # users="root $user"
    # for u in $users; do
    #     _max_days=$(chage -l $u |awk '/^Maximum/ {print $NF}')
    #     if [ $_max_days -ne $pass_max_days ]; then
    #         chage -M $pass_max_days $u
    #         echo "Set maximum password days '$pass_max_days' for '$u'"
    #     fi
    #     _min_days=$(chage -l $u |awk '/^Minimum/ {print $NF}')
    #     if [ $_min_days -ne $pass_min_days ]; then
    #         chage -m $pass_min_days $u
    #         echo "Set minimum password days '$pass_min_days' for '$u'"
    #     fi
    #     _warn_days=$(chage -l $u |awk '/warning/ {print $NF}')
    #     if [ $_warn_days -ne $pass_warn_days ]; then
    #         chage -W $pass_warn_days $u
    #         echo "Set warn password days '$pass_warn_days' for '$u'"
    #     fi
    # done
}

 # set_password_complex: Enforce password complexity with pam_pwquality (min length, classes, credits).
set_password_complex() {
    # password    requisite     pam_pwquality.so try_first_pass local_users_only retry=3 authtok_type= enforce_for_root minlen=8 minclass=3 ucredit=0 lcredit=0 dcredit=0 ocredit=0
    
    local file="/etc/pam.d/system-auth /etc/pam.d/password-auth"
    for f in $file; do
        local item=()
        for p in $password_complex; do
            if ! egrep -q "^\s*password\s+requisite\s+pam_pwquality\.so\s+.*${p}\b" $f; then
                if egrep -q "^\s*password\s+requisite\s+pam_pwquality\.so\s+.*${p%=*}" $f; then
                    # replace
                    sed -ri --follow-symlinks "/^\s*password\s+requisite\s+pam_pwquality\.so\s+/ s/${p%=*}=(-?[0-9]+)\b/${p}/" $f
                    item+=($p)
                else
                    # append
                    sed -ri --follow-symlinks "s/(^\s*password\s+requisite\s+pam_pwquality\.so\s+.*)/\1 ${p}/" $f
                    item+=($p)
                fi
            fi
        done

        if [ ${#item[@]} -gt 0 ]; then
            echo "Set '${item[@]}' in $f"
        fi
    done
}

 # set_password_history: Enforce password history (remember) with pam_pwhistory and ensure directive is present.
set_password_history() {
    # password    required     pam_pwhistory.so enforce_for_root remember=5

    local file="/etc/pam.d/system-auth /etc/pam.d/password-auth"
    pam_pwhistory="password    required      pam_pwhistory.so"

    for f in $file; do
        local item=()
        if ! egrep  -q "^\s*password\s+(requisite|required)\s+pam_pwhistory\.so" $f; then
            # insert
            sed -ri --follow-symlinks "/^\s*password\s+requisite\s+pam_pwquality\.so/a $pam_pwhistory" $f
        fi

        for p in $password_history; do
            if ! egrep  -q "^\s*password\s+(requisite|required)\s+pam_pwhistory\.so.*${p}\b" $f; then
                if egrep  -q "^\s*password\s+(requisite|required)\s+pam_pwhistory\.so.*${p%=*}" $f; then
                    # replace
                    sed -ri --follow-symlinks "/^\s*password\s+(requisite|required)\s+pam_pwhistory\.so/ s/${p%=*}=(-?[0-9]+)\b/${p}/" $f
                    item+=($p)
                else
                    # append
                    sed -ri --follow-symlinks "s/(^\s*password\s+(requisite|required)\s+pam_pwhistory\.so.*)/\1 ${p}/" $f
                    item+=($p)
                fi
            fi
        done

        if [ ${#item[@]} -gt 0 ]; then
            echo "Set '${item[@]}' in $f"
        fi
    done
}

 # set_password_faillock: Add pam_faillock rules for preauth/authfail/account and set deny/unlock_time parameters.
set_password_faillock() {
    local file="/etc/pam.d/system-auth /etc/pam.d/password-auth"
    faillock_preauth="auth        required      pam_faillock.so preauth silent audit"
    faillock_authfail="auth        [default=die] pam_faillock.so authfail audit"
    faillock_account="account     required      pam_faillock.so"

    for f in $file; do
        local item=()
        if ! egrep -q "^\s*auth\s+required\s+pam_faillock\.so" $f; then
            # insert
            sed -ri --follow-symlinks "/^\s*auth\s+sufficient\s+pam_unix\.so/i $faillock_preauth" $f
        fi
        if ! egrep -q "^\s*auth\s+\[default\=die\]\s+pam_faillock\.so" $f; then
            # insert
            sed -ri --follow-symlinks "/^\s*auth\s+sufficient\s+pam_unix\.so/a $faillock_authfail" $f
        fi
        if ! egrep -q "^\s*account\s+required\s+pam_faillock\.so" $f; then
            # insert
            sed -ri --follow-symlinks "/^\s*account\s+required\s+pam_unix\.so/i $faillock_account" $f
        fi

        for p in $password_faillock; do
            if ! egrep -q "^\s*auth\s+required\s+pam_faillock\.so\s+.*${p}\b" $f; then
                if egrep -q "^\s*auth\s+required\s+pam_faillock\.so\s+.*${p%=*}=(-?[0-9]+)\b" $f; then
                    # replace
                    sed -ri --follow-symlinks "/^\s*auth\s+required\s+pam_faillock\.so\s+/ s/${p%=*}=(-?[0-9]+)\b/${p}/" $f
                    item+=($p)
                else
                    # append
                    sed -ri --follow-symlinks "s/(^\s*auth\s+required\s+pam_faillock\.so\s+.*)/\1 ${p}/" $f
                    item+=($p)
                fi
            fi

            if ! egrep -q "^\s*auth\s+\[default\=die\]\s+pam_faillock\.so\s+.*${p}\b" $f; then
                if egrep -q "^\s*auth\s+\[default\=die\]\s+pam_faillock\.so\s+.*${p%=*}=(-?[0-9]+)\b" $f; then
                    # replace
                    sed -ri --follow-symlinks "/^\s*auth\s+\[default\=die\]\s+pam_faillock\.so\s+/ s/${p%=*}=(-?[0-9]+)\b/${p}/" $f
                    item+=($p)
                else
                    # append
                    sed -ri --follow-symlinks "s/(^\s*auth\s+\[default\=die\]\s+pam_faillock\.so\s+.*)/\1 ${p}/" $f
                    item+=($p)
                fi
            fi
        done

        if [ ${#item[@]} -gt 0 ]; then
            readarray -t array <<< "$(for i in "${item[@]}"; do echo "$i"; done | uniq)"
            echo "Set '${array[@]}' in $f"
        fi
    done
}

 # set_banner: Populate /etc/motd with a warning banner (colored when supported).
set_banner() {
#    RED="\033[1;31m"
#    GREEN="\033[1;32m"
    YELLOW="\033[1;33m"
    RESET="\033[0m"
    local file='/etc/motd'
    if [ ! -s $file ]; then
        echo -e "${YELLOW}${banner}${RESET}" > $file
        echo "Set banner in $file"
    fi
}

 # set_umask: Set default shell umask in /etc/profile.
set_umask() {
    local file="/etc/profile"
    source $file
    if [ $(umask) -ne $umask ]; then
        sed -ri '/^umask\s+/d' $file
        echo "umask $umask" >> $file
        echo "Set 'umask $umask' in $file"
    fi
}

 # set_ps1: Set a distinctive PS1 prompt on hosts matching the naming rule (e.g., production).
set_ps1() {
    local file=/etc/profile
    # source $file
    if hostname | grep -q "^p"; then
        if ! egrep -q "^\s*[^#]*PS1=" /etc/profile; then
            echo "export PS1=\"$ps1\"" >> $file
            echo "Set 'export PS1=\"$ps1\"' in $file"
        fi
    fi
}

 # set_profile: Export common interactive shell environment variables in /etc/profile.
set_profile() {
    local file=/etc/profile
    source $file
    while read line; do
        item=`echo $line | cut -d= -f1`
        value=`echo $line | cut -d= -f2`
        eval v='$'{$item}
        value=`eval echo $value`
        if [ "$v" != "$value" ]; then
            sed -ri "/^export\s+${item}=/d" $file
            echo "export $line" >> $file
            echo "Set 'export $line' in $file"
        fi
    done <<< "$etc_profile"
}

 # set_prompt_command: Log each executed command (user/IP/pwd/cmd) to syslog via PROMPT_COMMAND.
set_prompt_command() {
    local file=/etc/profile
    source $file
    if [ "$PROMPT_COMMAND" != "$prompt_command" ]; then
        sed -ri "/^\s*[^#]*PROMPT_COMMAND=/d" /etc/profile
        echo "export PROMPT_COMMAND='$prompt_command'" >> $file
        echo "Set 'export PROMPT_COMMAND' in $file"
    fi
}

 # set_sshd: Harden OpenSSH server settings (disable root login/empty passwords, etc.) and reload sshd.
set_sshd() {
    local file='/etc/ssh/sshd_config'
    local changed=0
    while read line; do
        item=` echo $line | cut -d' ' -f1 `
        value=` echo $line | cut -d' ' -f2 `
        # v=` sshd -T |grep -wi $item |awk '{print $2}' `
        v=` egrep -i "^\s*$item\s+" $file |awk '{print $2}' `
        if [ "$v" != "$value" ]; then
            sed -ri "/^\s*$item\s+/Id" $file
            echo $line >> $file
            echo "Set: '$line' in $file"
            changed=1
        fi
    done <<< "$sshd_config"

    if [ $changed -eq 1 ]; then
        systemctl reload sshd > /dev/null 2>&1
        echo "Reloaded sshd service"
    fi
}

 # set_logrotate: Adjust global logrotate retention count.
set_logrotate() {
    local file='/etc/logrotate.conf'
    r=$(awk '/^rotate/ {print $2}' $file)
    if [ $r -ne $logrotate ]; then
        sed -i "s/^rotate.*/rotate $logrotate/" $file
        echo "Set 'rotate $logrotate' in $file"
    fi
}

 # set_rsyslog: Route shell history logs (local1.*) to /var/log/history and restart rsyslog.
set_rsyslog() {
    local file='/etc/rsyslog.conf'
    if ! egrep -q "^\s*local1\.\*\s+/var/log/history" $file; then
        echo "local1.* /var/log/history" >> $file
        echo "Set 'local1.* /var/log/history' in $file"
        systemctl restart rsyslog > /dev/null 2>&1
        echo "Restarted rsyslog service"
    fi
}

 # set_auditd: Set auditd daemon parameters and reload auditd.
set_auditd() {
    local file="/etc/audit/auditd.conf"
    local changed=0
    while read line; do
        item=` awk -F '[ =]+' '{print $1}' <<< "$line" `
        value=` awk -F '[ =]+' '{print $2}' <<< "$line" `
        v=` grep "^\s*$item\b" $file | awk -F '[ =]+' '{print $2}' `
        if [ -z "$v" ]; then
            echo "$line" >> $file
            echo "Set '$line' in $file"
            changed=1
        elif [ "$v" != "$value" ]; then
            sed -i "s/^$item\b.*/$line/" $file
            echo "Set '$line' in $file"
            changed=1
        fi
    done <<< "$auditd_conf"

    if [ $changed -eq 1 ]; then
        service auditd reload > /dev/null
        echo "Reloaded auditd service"
        mark_changed
    fi
}

 # set_audit_rules: Append audit rules (identity, time-change, perm mods, etc.) and reload auditd.
set_audit_rules() {
    local file='/etc/audit/rules.d/audit.rules'
    local changed=0

    while read line; do
        if ! grep -q -- "$line" $file; then
            echo "$line" >> $file
            echo "Set '$line' in $file"
            changed=1
        fi
    done <<< "$audit_rules"

    if [ $changed -eq 1 ]; then
        service auditd reload > /dev/null
        echo "Reloaded auditd service"
        mark_changed
    fi
}

 # set_yum: Configure BaseOS/AppStream/EPEL repositories based on detected OS version.
set_yum() {
    # baseos
    if grep -qw "Red Hat" /etc/redhat-release; then
        OS=rhel
    elif grep -qw "CentOS" /etc/redhat-release; then
        OS=centos
    else
        return
    fi
    VERSION=` grep -o "[1-9]\.[1-9]" /etc/redhat-release |sed 's/\.//' `
    OSVERSION="${OS}${VERSION}"

    local file='/etc/yum.repos.d/base.repo'
    if [ $rhel_num -eq 7 -a ! -s $file ]; then
        cat <<EOF > $file
[BaseOS]
name=BaseOS
baseurl=http://mirrors.example.co.nz/$OSVERSION
gpgcheck=0
enabled=1
EOF
        echo "Set yum repository '$file'"
    elif [ $rhel_num -eq 8 -a ! -s $file ]; then
        cat <<EOF > $file
[BaseOS]
name=BaseOS
baseurl=http://mirrors.example.co.nz/$OSVERSION/BaseOS
gpgcheck=0
enabled=1

[AppStream]
name=AppStream
baseurl=http://mirrors.example.co.nz/$OSVERSION/AppStream
gpgcheck=0
enabled=1
EOF
    fi

    # epel
    local file='/etc/yum.repos.d/epel.repo'
    if [ $rhel_num -eq 7 -a ! -s $file ]; then
        cat <<EOF > $file
[epel7]
name=epel7
baseurl=http://mirrors.example.co.nz/epel/7/epel
gpgcheck=0
enabled=1
EOF
        echo "Set yum repository '$file'"
    elif [ $rhel_num -eq 8 -a ! -s $file ]; then
        cat <<EOF > $file
[epel8]
name=epel8
baseurl=http://mirrors.example.co.nz/epel/8/epel
gpgcheck=0
enabled=1
EOF
        echo "Set yum repository '$file'"
    fi
}

 # disable_usb: Block USB mass storage by mapping module load to /bin/true.
disable_usb() {
    local file='/etc/modprobe.d/usb-storage.conf'
    if ! grep -q '^install usb-storage /bin/true' /etc/modprobe.d/*.conf; then
        echo 'install usb-storage /bin/true' > $file
        echo "Set 'install usb-storage /bin/true' in $file"
    fi
}

 # disable_ctrl_alt_del: Mask the ctrl-alt-del.target to prevent accidental reboots.
disable_ctrl_alt_del() {
    if [ $(systemctl is-enabled ctrl-alt-del.target) != 'masked' ]; then
        systemctl mask ctrl-alt-del.target >/dev/null 2>&1
        echo "Disabled 'ctrl+alt+del' target" 
    fi
}

# Parameters: defaults for user, security policies, services, sysctl, and repository sources
user="isadmin"
userid="3009"
group="isadmin"
groupid="3001"
password="p@ssw0rd"

selinux="disabled"
runlevel="multi-user.target"
timezone="Pacific/Auckland"
logrotate=24
banner="###########################################\n       Production Environment\n         Authorized uses only. \nAll activity may be monitored and reported.\n###########################################"
umask="027"
ps1='\[\e[33;48m\][\u@\h \W]\\$ \[\e[m\]'
# prompt_command=$'{ msg=$(history 1 | { read x y; echo "$y"; }); ip=$(who am i | awk \'{if (NF==4) {print $2} else {print $5}}\' | sed "s/[()]//g"); logger -p local1.debug "[$(whoami)@$ip $(pwd)] $msg"; }'
prompt_command='{ msg=$(history 1 | { read x y; echo "$y"; }); ip=$(who am i | { read _ tty _ _ ip; [ -z "$ip" ] && ip=$tty; echo $ip | tr -d "()"; }); logger -p local1.debug "[$(whoami)@$ip $(pwd)] $msg"; }'

pass_max_days=99999
pass_min_days=0
pass_min_len=8
pass_warn_days=30
password_complex="enforce_for_root minlen=8 minclass=4 maxsequence=3 maxrepeat=3 difok=5 ucredit=-1 dcredit=-1 ocredit=-1 lcredit=-1"
password_history="enforce_for_root remember=3"
password_faillock="deny=5 unlock_time=600" # for root, add 'even_deny_root'

services_on="chronyd kdump rsyslog"
services_off="auditd libvirtd fcoe iscsi iscsid bluetooth avahi-daemon acpid autofs cups firewalld ntpdate postfix rhnsd rhsmcertd smartd NetworkManager abrtd abrt-ccpp"

etc_fstab="\
/home nosuid
/tmp noexec,nosuid,nodev
/var/tmp noexec,nosuid,nodev"

etc_profile='\
TMOUT=900
HISTSIZE=10000
HISTFILESIZE=10000
HISTTIMEFORMAT="%F %T "'

sshd_config="\
PermitEmptyPasswords no
PermitRootLogin no
GSSAPIAuthentication no
UseDNS no"

chrony_sources="\
server time.example.co.nz iburst"

auditd_conf="\
num_logs = 10
max_log_file = 100
flush = NONE"

ulimit="\
*    soft    nofile    65536
*    hard    nofile    65536
*    soft    nproc     65536
*    hard    nproc     65536"

sysctl="\
vm.swappiness = 10
net.ipv4.ip_forward = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1"

# cd /usr/share/doc/audit-2.8.5/rules; grep ^[^#] -h 10-base-config.rules 30-stig.rules 99-finalize.rules
audit_rules="\
-D
-b 8192
-f 1
-a always,exit -F arch=b32 -S adjtimex,settimeofday,stime -F key=time-change
-a always,exit -F arch=b64 -S adjtimex,settimeofday -F key=time-change
-a always,exit -F arch=b32 -S clock_settime -F a0=0x0 -F key=time-change
-a always,exit -F arch=b64 -S clock_settime -F a0=0x0 -F key=time-change
-w /etc/localtime -p wa -k time-change
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
-a always,exit -F arch=b32 -S sethostname,setdomainname -F key=system-locale
-a always,exit -F arch=b64 -S sethostname,setdomainname -F key=system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/hostname -p wa -k system-locale
-a always,exit -F dir=/etc/NetworkManager/ -F perm=wa -F key=system-locale
-a always,exit -F dir=/etc/selinux/ -F perm=wa -F key=MAC-policy
-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S lchown,fchown,chown,fchownat -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S open,creat,truncate,ftruncate,openat,open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b32 -S open,creat,truncate,ftruncate,openat,open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b64 -S open,truncate,ftruncate,creat,openat,open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b64 -S open,truncate,ftruncate,creat,openat,open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=unset -F key=export
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=unset -F key=export
-a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=unset -F key=delete
-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=unset -F key=delete
-w /etc/sudoers -p wa -k actions
-w /etc/sudoers.d/ -p wa -k actions"

# Main: guardrails, environment detection, then call functions in order

if [ -z "$1" ]; then
    echo -n "The script is only used on RHEL7/CentOS7. Are you sure to config the OS? [yes/no]: "
    read answer
    if ! [ "$answer" == "yes" -o "$answer" == "y" ]; then
        exit 1
    fi
elif [ "$1" != "yes" ]; then
    echo "Please confirm to config the OS."
    exit 1
fi

PATH=$PATH:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
rhel_num=$(uname -r |sed -r -n 's/^.*el([[:digit:]]).*$/\1/p')
# if [[ $rhel_num != [7-8] ]]; then
#     echo -e "The script is only used on RHEL/CentOS 7 and 8."
#     exit 1
# fi
if [[ $rhel_num != [7] ]]; then
    echo -e "The script is only used on RHEL7/CentOS7."
    exit 1
fi

## Call Function
create_user
set_sudo
#set_fstab
disable_selinux
set_runlevel # need reboot
#disable_ipv6 # need reboot
set_timezone
set_chrony
#enable_kdump # need reboot
# set_cron_user
set_cron_mail
set_service
set_ulimit
set_sysctl
set_password_age
set_password_complex
set_password_history
set_password_faillock
set_banner
#set_umask
set_ps1
set_profile
set_prompt_command
set_sshd
set_logrotate
set_rsyslog
#set_auditd
#set_audit_rules
set_yum
disable_usb
disable_ctrl_alt_del

# --- FINALIZE: materialize change/reboot markers for Ansible ---
if [ "$REBOOT" -eq 1 ]; then
    touch "$REBOOT_MARK"
fi
if [ "$CHANGED" -eq 1 ]; then
    touch "$CHANGE_MARK"
    echo "CHANGED=1"
fi