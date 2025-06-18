# Ansible Role for Server Hardening

This is an [Ansible](https://www.ansible.com/) role designed to enhance the
security of servers running on AlmaLinux, Debian, or Ubuntu.

It's [systemd](https://freedesktop.org/wiki/Software/systemd/) focused
and requires Ansible version 2.18 or higher.

The role supports the following operating systems:

- [AlmaLinux 9](https://wiki.almalinux.org/release-notes/#almalinux-9)
- [Debian 11 (Bullseye)](https://www.debian.org/releases/bullseye/)
- [Debian 12 (Bookworm)](https://www.debian.org/releases/bookworm/)
- [Ubuntu 22.04 (Jammy Jellyfish)](https://releases.ubuntu.com/jammy/)
- [Ubuntu 24.04 (Noble Numbat)](https://releases.ubuntu.com/noble/)

For those using AWS or Azure, there are also hardened Ubuntu Amazon
Machine Images (AMIs) and Azure virtual machine images available.

These are available in the [konstruktoid/hardened-images](https://github.com/konstruktoid/hardened-images)
repository. These images are built using [Packer](https://www.packer.io/) and
this Ansible role is used for configuration.

> **Note**
> Do not use this role without first testing in a non-operational environment.

> **Note**
> There is a [SLSA](https://slsa.dev/) artifact present under the
> [slsa action workflow](https://github.com/konstruktoid/ansible-role-hardening/actions/workflows/slsa.yml)
> for verification.

## Dependencies

None.

## Examples

### Requirements

```yaml
---
roles:
  - name: konstruktoid.hardening
    version: v3.3.0
    src: https://github.com/konstruktoid/ansible-role-hardening.git
    scm: git
```

### Playbook

```yaml
---
- name: Import and use the hardening role
  hosts: localhost
  any_errors_fatal: true
  tasks:
    - name: Import the hardening role
      ansible.builtin.import_role:
        name: konstruktoid.hardening
      vars:
        sshd_admin_net:
          - 10.0.2.0/24
          - 192.168.0.0/24
          - 192.168.1.0/24
        manage_suid_sgid_permissions: false
```

### Local playbook using git checkout

```yaml
---
- name: Checkout and configure konstruktoid.hardening
  hosts: localhost
  any_errors_fatal: true
  tasks:
    - name: Clone hardening repository
      become: true
      tags:
        - always
      block:
        - name: Install git
          ansible.builtin.package:
            name: git
            state: present

        - name: Checkout konstruktoid.hardening
          become: true
          ansible.builtin.git:
            repo: https://github.com/konstruktoid/ansible-role-hardening
            dest: /etc/ansible/roles/konstruktoid.hardening
            version: v3.3.0

        - name: Remove git
          ansible.builtin.package:
            name: git
            state: absent

    - name: Include the hardening role
      ansible.builtin.include_role:
        name: konstruktoid.hardening
      vars:
        sshd_allow_groups:
          - ubuntu
        sshd_login_grace_time: 60
        sshd_max_auth_tries: 10
        sshd_use_dns: false
        sshd_update_moduli: true
```

## Note regarding UFW firewall rules

Instead of resetting `ufw` every run and by doing so causing network traffic
disruption, the role deletes every `ufw` rule without
`comment: ansible managed` task parameter and value.

The role also sets default deny policies, which means that firewall rules
needs to be created for any additional ports except those specified in
the `sshd_ports` and `ufw_outgoing_traffic` variables.

See [ufw(8)](https://manpages.ubuntu.com/manpages/noble/en/man8/ufw.8.html)
for more information.

## Task Execution and Structure

See [STRUCTURE.md](STRUCTURE.md) for tree of the role structure.

## Role testing

See [TESTING.md](TESTING.md).

## Role Variables with defaults

### ./defaults/main/adduser.yml

```yaml
manage_adduser_conf: true
```

### ./defaults/main/aide.yml

```yaml
manage_aide: true

aide_checksums: sha512
aide_dir_exclusions:
  - /var/lib/docker
  - /var/lib/lxcfs
  - /var/lib/private/systemd
  - /var/log/audit
  - /var/log/journal
```

### ./defaults/main/apparmor.yml

```yaml
manage_apparmor: true
```

### ./defaults/main/apport.yml

```yaml
disable_apport: true
```

### ./defaults/main/auditd.yml

```yaml
manage_auditd: true

auditd_apply_audit_rules: true
auditd_action_mail_acct: root
auditd_admin_space_left_action: suspend
auditd_disk_error_action: suspend
auditd_disk_full_action: suspend
auditd_enable_flag: 2
auditd_flush: incremental_async
auditd_max_log_file: 20
auditd_max_log_file_action: rotate
auditd_mode: 1
auditd_num_logs: 5
auditd_space_left: 75
auditd_space_left_action: email
grub_audit_backlog_cmdline: audit_backlog_limit=8192
grub_audit_cmdline: audit=1
```

### ./defaults/main/automatic_updates.yml

```yaml
automatic_updates:
  enabled: true
  only_security: true
  reboot: false
  reboot_from_time: "2:00"
  reboot_time_margin_mins: 20
```

### ./defaults/main/compilers.yml

```yaml
manage_compilers: true

compilers:
  - as
  - cargo
  - cc
  - cc-[0-9]*
  - clang-[0-9]*
  - gcc
  - gcc-[0-9]*
  - go
  - make
  - rustc
```

### ./defaults/main/cron.yml

```yaml
manage_cron: true
```

### ./defaults/main/crypto_policies.yml

```yaml
set_crypto_policy: true
crypto_policy: DEFAULT:NO-SHA1
```

### ./defaults/main/ctrlaltdel.yml

```yaml
disable_ctrlaltdel: true
```

### ./defaults/main/disablewireless.yml

```yaml
disable_wireless: false
```

### ./defaults/main/dns.yml

```yaml
manage_resolved: true

dns:
  - 1.1.1.2
  - 9.9.9.9
fallback_dns:
  - 1.0.0.2
  - 149.112.112.112
dnssec: allow-downgrade
dns_over_tls: opportunistic
```

### ./defaults/main/fstab.yml

```yaml
manage_fstab: true
```

### ./defaults/main/hosts.yml

```yaml
manage_hosts: true
```

### ./defaults/main/ipv6.yml

```yaml
disable_ipv6: false
sysctl_net_ipv6_conf_accept_ra_rtr_pref: 0

ipv6_disable_sysctl_settings:
  net.ipv6.conf.all.disable_ipv6: 1
  net.ipv6.conf.default.disable_ipv6: 1

ipv6_sysctl_settings:
  net.ipv6.conf.all.accept_ra: 0
  net.ipv6.conf.all.accept_redirects: 0
  net.ipv6.conf.all.accept_source_route: 0
  net.ipv6.conf.all.forwarding: 0
  net.ipv6.conf.all.use_tempaddr: 2
  net.ipv6.conf.default.accept_ra: 0
  net.ipv6.conf.default.accept_ra_defrtr: 0
  net.ipv6.conf.default.accept_ra_pinfo: 0
  net.ipv6.conf.default.accept_ra_rtr_pref: 0
  net.ipv6.conf.default.accept_redirects: 0
  net.ipv6.conf.default.accept_source_route: 0
  net.ipv6.conf.default.autoconf: 0
  net.ipv6.conf.default.dad_transmits: 0
  net.ipv6.conf.default.max_addresses: 1
  net.ipv6.conf.default.router_solicitations: 0
  net.ipv6.conf.default.use_tempaddr: 2
```

### ./defaults/main/issue.yml

```yaml
manage_issue: true
```

### ./defaults/main/journal.yml

```yaml
manage_journal: true

rsyslog_filecreatemode: "0640"

journald_compress: true
journald_forwardtosyslog: false
journald_storage: persistent

journald_permissions: "2640"
journald_group: "systemd-journal"
journald_user: "root"
journald_system_max_use: ""
```

### ./defaults/main/kernel.yml

```yaml
manage_kernel: true
allow_virtual_system_calls: true
enable_page_poisoning: true
kernel_lockdown: false
page_table_isolation: true
slub_debugger_poisoning: false
```

### ./defaults/main/limits.yml

```yaml
manage_limits: true
limit_nofile_hard: 1024
limit_nofile_soft: 512
limit_nproc_hard: 1024
limit_nproc_soft: 512
```

### ./defaults/main/lockroot.yml

```yaml
disable_root_account: true
```

### ./defaults/main/logind.yml

```yaml
manage_logind: true
logind:
  killuserprocesses: true
  killexcludeusers:
    - root
  idleaction: lock
  idleactionsec: 15min
  removeipc: true
```

### ./defaults/main/logindefs.yml

```yaml
manage_login_defs: true
```

### ./defaults/main/misc.yml

```yaml
reboot_ubuntu: false
```

### ./defaults/main/module_blocklists.yml

```yaml
manage_kernel_modules: true

fs_modules_blocklist:
  - cramfs
  - freevxfs
  - hfs
  - hfsplus
  - jffs2
  - squashfs
  - udf

misc_modules_blocklist:
  - bluetooth
  - bnep
  - btusb
  - can
  - cpia2
  - firewire-core
  - floppy
  - ksmbd
  - n_hdlc
  - net-pf-31
  - pcspkr
  - soundcore
  - thunderbolt
  - usb-midi
  - usb-storage
  - uvcvideo
  - v4l2_common

net_modules_blocklist:
  - atm
  - dccp
  - sctp
  - rds
  - tipc
```

### ./defaults/main/motdnews.yml

```yaml
manage_motdnews: true
```

### ./defaults/main/mount.yml

```yaml
manage_mounts: true
hide_pid: 2
process_group: 0
```

### ./defaults/main/netplan.yml

```yaml
manage_netplan: true
```

### ./defaults/main/ntp.yml

```yaml
manage_timesyncd: true

fallback_ntp:
  - ntp.netnod.se
  - ntp.ubuntu.com
ntp:
  - 2.pool.ntp.org
  - time.nist.gov
```

### ./defaults/main/packagemgmt.yml

```yaml
manage_package_managers: true
apt_hardening_options:
  - Acquire::AllowDowngradeToInsecureRepositories "false";
  - Acquire::AllowInsecureRepositories "false";
  - Acquire::http::AllowRedirect "false";
  - APT::Get::AllowUnauthenticated "false";
  - APT::Get::AutomaticRemove "true";
  - APT::Install-Recommends "false";
  - APT::Install-Suggests "false";
  - APT::Periodic::AutocleanInterval "7";
  - APT::Sandbox::Seccomp "1";
  - Unattended-Upgrade::Remove-Unused-Dependencies "true";
  - Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
```

### ./defaults/main/packages.yml

```yaml
manage_packages: true
system_upgrade: true

packages_blocklist:
  - apport*
  - autofs
  - avahi*
  - avahi-*
  - beep
  - ftp
  - git
  - inetutils-telnet
  - pastebinit
  - popularity-contest
  - prelink
  - rpcbind
  - rsh*
  - rsync
  - talk*
  - telnet*
  - tftp*
  - tnftp
  - tuned
  - whoopsie
  - xinetd
  - yp-tools
  - ypbind

packages_debian:
  - acct
  - apparmor-profiles
  - apparmor-utils
  - apt-show-versions
  - audispd-plugins
  - auditd
  - cracklib-runtime
  - curl
  - debsums
  - gnupg2
  - libpam-apparmor
  - libpam-cap
  - libpam-modules
  - libpam-tmpdir
  - lsb-release
  - needrestart
  - openssh-server
  - postfix
  - rsyslog
  - sysstat
  - systemd-journal-remote
  - tcpd
  - vlock
  - wamerican

packages_redhat:
  - audispd-plugins
  - audit
  - cracklib
  - curl
  - gnupg2
  - openssh-server
  - needrestart
  - postfix
  - psacct
  - python3-dnf-plugin-post-transaction-actions
  - rsyslog
  - rsyslog-gnutls
  - systemd-journal-remote
  - vlock
  - words

packages_ubuntu:
  - fwupd
  - secureboot-db
  - snapd
```

### ./defaults/main/password.yml

```yaml
manage_password: true
manage_pam: true
manage_faillock: true
manage_pwquality: true

faillock:
  admin_group: []
  audit: true
  deny: 5
  dir: /var/run/faillock
  even_deny_root: true
  fail_interval: 900
  local_users_only: true
  no_log_info: false
  nodelay: true
  root_unlock_time: 600
  silent: false
  unlock_time: 600

login_defs:
  login_retries: 5
  login_timeout: 60
  pass_max_days: 60
  pass_min_days: 1
  pass_warn_age: 7

password_remember: 24

pwquality:
  dcredit: -1
  dictcheck: true
  dictpath: ""
  difok: 8
  enforce_for_root: true
  enforcing: true
  gecoscheck: true
  lcredit: -1
  local_users_only: true
  maxclassrepeat: 4
  maxrepeat: 3
  maxsequence: 3
  minclass: 4
  minlen: 15
  ocredit: -1
  retry: 3
  ucredit: -1
  usercheck: true
  usersubstr: 3
```

### ./defaults/main/path.yml

```yaml
manage_path: true
```

### ./defaults/main/postfix.yml

```yaml
manage_postfix: true
```

### ./defaults/main/prelink.yml

```yaml
disable_prelink: true
```

### ./defaults/main/rkhunter.yml

```yaml
manage_rkhunter: true

rkhunter_allow_ssh_prot_v1: false
rkhunter_allow_ssh_root_user: false
rkhunter_mirrors_mode: 0
rkhunter_update_mirrors: true
rkhunter_web_cmd: curl -fsSL
```

### ./defaults/main/rootaccess.yml

```yaml
manage_root_access: true
```

### ./defaults/main/sshd.yml

```yaml
manage_ssh: true

sshd_accept_env: LANG LC_*
sshd_admin_net:
  - 192.168.0.0/24
  - 192.168.1.0/24
sshd_allow_agent_forwarding: false
sshd_allow_groups:
  - sudo
sshd_allow_tcp_forwarding: false
sshd_allow_users:
  - "{{ ansible_user | default(lookup('ansible.builtin.env', 'USER')) }}"
sshd_authentication_methods: any
sshd_authorized_principals_file: /etc/ssh/auth_principals/%u
sshd_banner: /etc/issue.net
sshd_ca_signature_algorithms:
  - ecdsa-sha2-nistp384
  - ecdsa-sha2-nistp521
  - ssh-ed25519
  - rsa-sha2-512
sshd_kbd_interactive_authentication: false
sshd_ciphers:
  - chacha20-poly1305@openssh.com
  - aes256-gcm@openssh.com
  - aes256-ctr
sshd_client_alive_count_max: 1
sshd_client_alive_interval: 200
sshd_compression: false
sshd_config_d_force_clear: false
sshd_config_force_replace: false
sshd_debian_banner: false
sshd_deny_groups: []
sshd_deny_users: []
sshd_gateway_ports: false
sshd_gssapi_authentication: false
sshd_host_key_algorithms:
  - ssh-ed25519-cert-v01@openssh.com
  - ssh-rsa-cert-v01@openssh.com
  - ssh-ed25519
  - ecdsa-sha2-nistp521-cert-v01@openssh.com
  - ecdsa-sha2-nistp384-cert-v01@openssh.com
  - ecdsa-sha2-nistp521
  - ecdsa-sha2-nistp384
sshd_host_keys_files: []
sshd_host_keys_group: root
sshd_host_keys_mode: "0600"
sshd_host_keys_owner: root
sshd_hostbased_authentication: false
sshd_ignore_rhosts: true
sshd_ignore_user_known_hosts: true
sshd_kerberos_authentication: false
sshd_kex_algorithms:
  - curve25519-sha256@libssh.org
  - diffie-hellman-group16-sha512
  - diffie-hellman-group18-sha512
  - ecdh-sha2-nistp521
  - ecdh-sha2-nistp384
sshd_listen:
  - 0.0.0.0
sshd_log_level: verbose
sshd_login_grace_time: 20
sshd_macs:
  - hmac-sha2-512-etm@openssh.com
  - hmac-sha2-256-etm@openssh.com
  - hmac-sha2-512
  - hmac-sha2-256
sshd_match_addresses: {}
sshd_match_groups: {}
sshd_match_local_ports: {}
sshd_match_users: {}
sshd_max_auth_tries: 3
sshd_max_sessions: 3
sshd_max_startups: 10:30:60
sshd_password_authentication: false
sshd_permit_empty_passwords: false
sshd_permit_root_login: false
sshd_permit_tunnel: false
sshd_permit_user_environment: false
sshd_ports:
  - 22
sshd_print_last_log: true
sshd_print_motd: false
sshd_print_pam_motd: false
sshd_rekey_limit: 512M 1h
sshd_required_ecdsa_size: 521
sshd_required_rsa_size: 4096
sshd_sftp_enabled: true
sshd_sftp_chroot: true
sshd_sftp_chroot_dir: "%h"
sshd_sftp_only_group: ""
sshd_sftp_subsystem: internal-sftp -f LOCAL6 -l INFO
sshd_strict_modes: true
sshd_syslog_facility: auth
sshd_tcp_keep_alive: false
sshd_trusted_user_ca_keys_base64: ""
sshd_trusted_user_ca_keys_file: /etc/ssh/trusted-user-ca-keys.pem
sshd_update_moduli: false
sshd_update_moduli_url: https://raw.githubusercontent.com/konstruktoid/ssh-moduli/main/moduli
sshd_use_dns: false
sshd_use_pam: true
sshd_use_privilege_separation: sandbox
sshd_x11_forwarding: false
```

### ./defaults/main/sudo.yml

```yaml
manage_sudo: true
```

### ./defaults/main/suid_sgid_blocklist.yml

```yaml
manage_suid_sgid_permissions: true
suid_sgid_blocklist:
  - 7z
  - aa-exec
  - ab
  - agetty
  - alpine
  - ansible-playbook
  - ansible-test
  - aoss
  - apache2ctl
  - apt
  - apt-get
  - ar
  - aria2c
  - arj
  - arp
  - as
  - ascii-xfr
  - ascii85
  - ash
  - aspell
  - at
  - atobm
  - awk
  - aws
  - base32
  - base58
  - base64
  - basenc
  - basez
  - bash
  - batcat
  - bc
  - bconsole
  - bpftrace
  - bridge
  - bsd-write
  - bundle
  - bundler
  - busctl
  - busybox
  - byebug
  - bzip2
  - c89
  - c99
  - cabal
  - cancel
  - capsh
  - cat
  - cdist
  - certbot
  - chage
  - check_by_ssh
  - check_cups
  - check_log
  - check_memory
  - check_raid
  - check_ssl_cert
  - check_statusfile
  - chfn
  - chmod
  - choom
  - chown
  - chroot
  - chsh
  - clamscan
  - cmp
  - cobc
  - column
  - comm
  - composer
  - cowsay
  - cowthink
  - cp
  - cpan
  - cpio
  - cpulimit
  - crash
  - crontab
  - csh
  - csplit
  - csvtool
  - cupsfilter
  - curl
  - cut
  - dash
  - date
  - dc
  - dd
  - debugfs
  - dialog
  - diff
  - dig
  - distcc
  - dmesg
  - dmidecode
  - dmsetup
  - dnf
  - docker
  - dos2unix
  - dosbox
  - dotnet
  - dpkg
  - dstat
  - dvips
  - easy_install
  - eb
  - ed
  - efax
  - elvish
  - emacs
  - enscript
  - env
  - eqn
  - espeak
  - ex
  - exiftool
  - expand
  - expect
  - facter
  - file
  - find
  - finger
  - fish
  - flock
  - fmt
  - fold
  - fping
  - ftp
  - fusermount
  - gawk
  - gcc
  - gcloud
  - gcore
  - gdb
  - gem
  - genie
  - genisoimage
  - ghc
  - ghci
  - gimp
  - ginsh
  - git
  - grc
  - grep
  - gtester
  - gzip
  - hd
  - head
  - hexdump
  - highlight
  - hping3
  - iconv
  - iftop
  - install
  - ionice
  - ip
  - irb
  - ispell
  - jjs
  - joe
  - join
  - journalctl
  - jq
  - jrunscript
  - jtag
  - julia
  - knife
  - ksh
  - ksshell
  - ksu
  - kubectl
  - latex
  - latexmk
  - ld.so
  - ldconfig
  - less
  - lftp
  - links
  - ln
  - loginctl
  - logsave
  - look
  - lp
  - ltrace
  - lua
  - lualatex
  - luatex
  - lwp-download
  - lwp-request
  - mail
  - make
  - man
  - mawk
  - minicom
  - mksh
  - mksh-static
  - mlocate
  - more
  - mosquitto
  - mount
  - mount.nfs
  - msfconsole
  - msgattrib
  - msgcat
  - msgconv
  - msgfilter
  - msgmerge
  - msguniq
  - mtr
  - multitime
  - mv
  - mysql
  - nano
  - nasm
  - nawk
  - nc
  - ncdu
  - ncftp
  - neofetch
  - netfilter-persistent
  - newgrp
  - nft
  - nice
  - nl
  - nm
  - nmap
  - node
  - nohup
  - npm
  - nroff
  - nsenter
  - ntfs-3g
  - ntpdate
  - octave
  - od
  - openssl
  - openvpn
  - openvt
  - opkg
  - pandoc
  - paste
  - pax
  - pdb
  - pdflatex
  - pdftex
  - perf
  - perl
  - perlbug
  - pexec
  - pg
  - php
  - pic
  - pico
  - pidstat
  - ping
  - ping6
  - pip
  - pkexec
  - pkg
  - posh
  - pppd
  - pr
  - pry
  - psad
  - psftp
  - psql
  - ptx
  - puppet
  - pwsh
  - python
  - rake
  - rbash
  - rc
  - readelf
  - red
  - redcarpet
  - redis
  - restic
  - rev
  - rlogin
  - rlwrap
  - rpm
  - rpmdb
  - rpmquery
  - rpmverify
  - rsync
  - rtorrent
  - ruby
  - run-mailcap
  - run-parts
  - runscript
  - rview
  - rvim
  - sash
  - scanmem
  - scp
  - screen
  - script
  - scrot
  - sed
  - service
  - setarch
  - setfacl
  - setlock
  - sftp
  - sg
  - sh
  - shuf
  - slsh
  - smbclient
  - snap
  - socat
  - socket
  - soelim
  - softlimit
  - sort
  - split
  - sqlite3
  - sqlmap
  - ss
  - ssh
  - ssh-agent
  - ssh-keygen
  - ssh-keyscan
  - sshpass
  - start-stop-daemon
  - stdbuf
  - strace
  - strings
  - su
  - sysctl
  - systemctl
  - systemd-resolve
  - tac
  - tail
  - tar
  - task
  - taskset
  - tasksh
  - tbl
  - tclsh
  - tcpdump
  - tcsh
  - tdbtool
  - tee
  - telnet
  - terraform
  - tex
  - tftp
  - tic
  - time
  - timedatectl
  - timeout
  - tmate
  - tmux
  - top
  - torify
  - torsocks
  - traceroute6.iputils
  - troff
  - tshark
  - ul
  - umount
  - unexpand
  - uniq
  - unshare
  - unsquashfs
  - unzip
  - update-alternatives
  - uudecode
  - uuencode
  - vagrant
  - valgrind
  - varnishncsa
  - vi
  - view
  - vigr
  - vim
  - vimdiff
  - vipw
  - virsh
  - volatility
  - w3m
  - wall
  - watch
  - wc
  - wget
  - whiptail
  - whois
  - wireshark
  - wish
  - write
  - xargs
  - xdg-user-dir
  - xdotool
  - xelatex
  - xetex
  - xmodmap
  - xmore
  - xpad
  - xxd
  - xz
  - yarn
  - yash
  - yelp
  - yum
  - zathura
  - zip
  - zsh
  - zsoelim
  - zypper
```

### ./defaults/main/sysctl.yml

```yaml
manage_sysctl: true

usr_lib_sysctl_d_dir: false
sysctl_conf_dir: "{{ '/usr/lib/sysctl.d' if usr_lib_sysctl_d_dir else '/etc/sysctl.d' }}"

sysctl_dev_tty_ldisc_autoload: 0

apparmor_sysctl_settings:
  kernel.apparmor_display_secid_mode: 0
  kernel.apparmor_restrict_unprivileged_io_uring: 0
  kernel.apparmor_restrict_unprivileged_unconfined: 1
  kernel.apparmor_restrict_unprivileged_userns: 1
  kernel.apparmor_restrict_unprivileged_userns_complain: 0
  kernel.apparmor_restrict_unprivileged_userns_force: 0
  kernel.unprivileged_userns_apparmor_policy: 1

conntrack_sysctl_settings:
  net.netfilter.nf_conntrack_max: 2000000
  net.netfilter.nf_conntrack_tcp_loose: 0

generic_sysctl_settings:
  fs.protected_fifos: 2
  fs.protected_hardlinks: 1
  fs.protected_regular: 2
  fs.protected_symlinks: 1
  fs.suid_dumpable: 0
  kernel.core_pattern: "|/bin/false"
  kernel.core_uses_pid: 1
  kernel.dmesg_restrict: 1
  kernel.kptr_restrict: 2
  kernel.panic: 60
  kernel.panic_on_oops: 1
  kernel.perf_event_paranoid: 2
  kernel.randomize_va_space: 2
  kernel.sysrq: 0
  kernel.unprivileged_bpf_disabled: 1
  kernel.yama.ptrace_scope: 2
  net.core.bpf_jit_harden: 2
  user.max_user_namespaces: 62967

ipv4_sysctl_settings:
  net.ipv4.conf.all.accept_redirects: 0
  net.ipv4.conf.all.accept_source_route: 0
  net.ipv4.conf.all.log_martians: 1
  net.ipv4.conf.all.rp_filter: 1
  net.ipv4.conf.all.secure_redirects: 1
  net.ipv4.conf.all.send_redirects: 0
  net.ipv4.conf.all.shared_media: 1
  net.ipv4.conf.default.accept_redirects: 0
  net.ipv4.conf.default.accept_source_route: 0
  net.ipv4.conf.default.log_martians: 1
  net.ipv4.conf.default.rp_filter: 1
  net.ipv4.conf.default.secure_redirects: 1
  net.ipv4.conf.default.send_redirects: 0
  net.ipv4.conf.default.shared_media: 1
  net.ipv4.icmp_echo_ignore_broadcasts: 1
  net.ipv4.icmp_ignore_bogus_error_responses: 1
  net.ipv4.ip_forward: 0
  net.ipv4.tcp_challenge_ack_limit: 2147483647
  net.ipv4.tcp_invalid_ratelimit: 500
  net.ipv4.tcp_max_syn_backlog: 20480
  net.ipv4.tcp_rfc1337: 1
  net.ipv4.tcp_syn_retries: 5
  net.ipv4.tcp_synack_retries: 2
  net.ipv4.tcp_syncookies: 1
  net.ipv4.tcp_timestamps: 1
```

### ./defaults/main/systemdconf.yml

```yaml
manage_systemd: true
```

### ./defaults/main/templates.yml

```yaml
adduser_conf_template: etc/adduser.conf.j2
common_account_template: etc/pam.d/common-account.j2
common_auth_template: etc/pam.d/common-auth.j2
common_password_template: etc/pam.d/common-password.j2
coredump_conf_template: etc/systemd/coredump.conf.j2
faillock_conf_template: etc/security/faillock.conf.j2
hardening_rules_template: etc/audit/rules.d/hardening.rules.j2
hosts_allow_template: etc/hosts.allow.j2
hosts_deny_template: etc/hosts.deny.j2
initpath_sh_template: etc/profile.d/initpath.sh.j2
issue_template: etc/issue.j2
journald_conf_template: etc/systemd/journald.conf.j2
limits_conf_template: etc/security/limits.conf.j2
login_defs_template: etc/login.defs.j2
login_template: etc/pam.d/login.j2
logind_conf_template: etc/systemd/logind.conf.j2
logrotate_conf_template: etc/logrotate.conf.j2
motd_template: etc/motd.j2
pwquality_conf_template: etc/security/pwquality.conf.j2
resolved_conf_template: etc/systemd/resolved.conf.j2
rkhunter_template: etc/default/rkhunter.j2
ssh_config_template: etc/ssh/ssh_config.j2
sshd_config_template: etc/ssh/sshd_config.j2
sshd_tmpfiles_template: usr/lib/tmpfiles.d/ssh.conf.j2
sysctl_apparmor_config_template: etc/sysctl/sysctl.apparmor.conf.j2
sysctl_ipv6_config_template: etc/sysctl/sysctl.ipv6.conf.j2
sysctl_main_config_template: etc/sysctl/sysctl.main.conf.j2
system_conf_template: etc/systemd/system.conf.j2
timesyncd_conf_template: etc/systemd/timesyncd.conf.j2
tmp_mount_template: etc/systemd/tmp.mount.j2
unattended_upgrades_template: etc/apt/apt.conf.d/50unattended-upgrades.j2
user_conf_template: etc/systemd/user.conf.j2
useradd_template: etc/default/useradd.j2
```

### ./defaults/main/ufw.yml

```yaml
manage_ufw: true

ufw_outgoing_traffic:
  - { port: 22, proto: "tcp" }
  - 53
  - { port: 80, proto: "tcp" }
  - { port: 123, proto: "udp" }
  - { port: 443, proto: "tcp" }
  - 853
  - { port: 4460, proto: "tcp" }

ufw_rate_limit: false
```

### ./defaults/main/umask.yml

```yaml
session_timeout: 900
umask_value: "077"
```

### ./defaults/main/usbguard.yml

```yaml
manage_usbguard: true

usbguard_configuration_file: /etc/usbguard/usbguard-daemon.conf
usbguard_rulefile: /etc/usbguard/rules.conf

usbguard_auditbackend: LinuxAudit
usbguard_auditfilepath: /var/log/usbguard/usbguard-audit.log
usbguard_authorizeddefault: none
usbguard_devicemanagerbackend: uevent
usbguard_deviceruleswithport: false
usbguard_hidepii: false
usbguard_implicitpolicytarget: block
usbguard_inserteddevicepolicy: apply-policy
usbguard_ipcaccesscontrolfiles: /etc/usbguard/IPCAccessControl.d/
usbguard_ipcallowedgroups:
  - plugdev
  - root
  - wheel
usbguard_ipcallowedusers:
  - root
usbguard_presentcontrollerpolicy: keep
usbguard_presentdevicepolicy: apply-policy
usbguard_restorecontrollerdevicestate: false
```

### ./defaults/main/users.yml

```yaml
manage_users: true
delete_users:
  - games
  - gnats
  - irc
  - list
  - news
  - sync
  - uucp
```

## Recommended Reading

[Comparing the DISA STIG and CIS Benchmark values](https://github.com/konstruktoid/publications/blob/master/ubuntu_comparing_guides_benchmarks.md)

[Center for Internet Security Linux Benchmarks](https://www.cisecurity.org/cis-benchmarks/)

[Common Configuration Enumeration](https://nvd.nist.gov/cce/index.cfm)

[DISA Security Technical Implementation Guides](https://public.cyber.mil/stigs/downloads/?_dl_facet_stigs=operating-systems%2Cunix-linux)

[SCAP Security Guides](https://complianceascode.github.io/content-pages/guides/index.html)

[Security focused systemd configuration](https://github.com/konstruktoid/hardening/blob/master/systemd.adoc)

## Contributing

Do you want to contribute? Great! Contributions are always welcome,
no matter how large or small. If you found something odd, feel free to submit a
issue, improve the code by creating a pull request, or by
[sponsoring this project](https://github.com/sponsors/konstruktoid).

## License

Apache License Version 2.0

## Author Information

[https://github.com/konstruktoid](https://github.com/konstruktoid "github.com/konstruktoid")
