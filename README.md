# Hardening - the Ansible role

An [Ansible](https://www.ansible.com/) role to make a CentOS, Debian or Ubuntu
server a bit more secure,
[systemd edition](https://freedesktop.org/wiki/Software/systemd/).

Requires Ansible >= 2.9.

Available on
[Ansible Galaxy](https://galaxy.ansible.com/konstruktoid/hardening).

```shell
Do not use this role without first testing in a non-operational environment.
```

## Dependencies

None.

## Example Playbook

```shell
---
- hosts: all
  serial: 50%
    - { role: konstruktoid.hardening, sshd_admin_net: [10.0.0.0/24] }
...
```

### Note regarding Debian family UFW firewall rules

Instead of resetting `ufw` every run and by doing so causing network traffic
disruption, the role deletes every `ufw` rule without
`comment: ansible managed` task parameter and value.

The role also sets default deny policies, which means that firewall rules
needs to be created for any additional ports except those specified in
the `sshd_port` and `ufw_outgoing_traffic` variables.

## Task Execution and Structure

See [STRUCTURE.md](STRUCTURE.md) for a detailed map regarding all tasks
and the role structure.

## Role testing

See [TESTING.md](TESTING.md).

## Role Variables with defaults

### ./defaults/main/auditd.yml

```yaml
auditd_action_mail_acct: root
auditd_admin_space_left_action: suspend
auditd_max_log_file_action: keep_logs
auditd_mode: 1
auditd_space_left_action: email
grub_audit_backlog_cmdline: audit_backlog_limit=8192
grub_audit_cmdline: audit=1
```

Enable `auditd` at boot using Grub.

`auditd_action_mail_acct` should be a valid email address or alias.

`auditd_admin_space_left_action` defines what action to take when the system has
detected that it is low on disk space. `suspend` will cause the audit daemon to
stop writing records to the disk.

`auditd_max_log_file_action` sets what action to take when the system has
detected that the max file size limit has been reached. `keep_logs` causes the
audit daemon to rotate the logs.

`auditd_space_left_action` tells the system what action to take when the system
has detected that it is low on disk space. `email` means that it will send a
warning to the email account specified in `action_mail_acct` as well as
sending the message to syslog.

`auditd_mode` sets `auditd` failure mode, 0=silent 1=printk 2=panic.

[auditd.conf(5)](https://man7.org/linux/man-pages/man5/auditd.conf.5.html)

### ./defaults/main/compilers.yml

```yaml
compilers:
  - /bin/as
  - /bin/cc
  - /bin/gcc
  - /bin/make
  - /usr/bin/as
  - /usr/bin/cc
  - /usr/bin/gcc
  - /usr/bin/make
```

List of compilers that will be restricted to the root user.

### ./defaults/main/dns.yml

```yaml
dns: 127.0.0.1
dnssec: allow-downgrade
fallback_dns: 1.1.1.1 9.9.9.9
```

IPv4 and IPv6 addresses to use as system and fallback DNS servers.
If `dnssec` is set to "allow-downgrade" DNSSEC validation is attempted, but if
the server does not support DNSSEC properly, DNSSEC mode is automatically
disabled. [systemd](https://github.com/konstruktoid/hardening/blob/master/systemd.adoc#etcsystemdresolvedconf)
option.

### ./defaults/main/firewall.yml

```yaml
ufw_outgoing_traffic:
  - 22
  - 53
  - 80
  - 123
  - 443
  - 853
```

Open `ufw` ports, allowing outgoing traffic.

### ./defaults/main/limits.yml

```yaml
limit_nofile_hard: 1024
limit_nofile_soft: 512
limit_nproc_hard: 1024
limit_nproc_soft: 512
```

Maximum number of processes and open files.

### ./defaults/main/misc.yml

```yaml
reboot_ubuntu: false
redhat_rpm_key:
  - 567E347AD0044ADE55BA8A5F199E2F91FD431D51
  - 47DB287789B21722B6D95DDE5326810137017186
```

If `reboot_ubuntu: true` an Ubuntu node will be rebooted if required.

`redhat_rpm_key` are [RedHat Product Signing Keys](https://access.redhat.com/security/team/key/)

### ./defaults/main/module_blocklists.yml

```yaml
fs_modules_blocklist:
  - cramfs
  - freevxfs
  - hfs
  - hfsplus
  - jffs2
  - squashfs
  - udf
  - vfat
misc_modules_blocklist:
  - bluetooth
  - bnep
  - btusb
  - cpia2
  - firewire-core
  - floppy
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
  - dccp
  - sctp
  - rds
  - tipc
```

Blocked kernel modules.

### ./defaults/main/ntp.yml

```yaml
fallback_ntp: 2.ubuntu.pool.ntp.org 3.ubuntu.pool.ntp.org
ntp: 0.ubuntu.pool.ntp.org 1.ubuntu.pool.ntp.org
```

NTP server host names or IP addresses. [systemd](https://github.com/konstruktoid/hardening/blob/master/systemd.adoc#etcsystemdtimesyncdconf)
option.

### ./defaults/main/packages.yml

```yaml
system_upgrade: 'yes'
packages_blocklist:
  - apport*
  - autofs
  - avahi*
  - avahi-*
  - beep
  - git
  - pastebinit
  - popularity-contest
  - rpcbind
  - rsh*
  - rsync
  - talk*
  - telnet*
  - tftp*
  - whoopsie
  - xinetd
  - yp-tools
  - ypbind
packages_debian:
  - acct
  - aide-common
  - apparmor-profiles
  - apparmor-utils
  - apt-show-versions
  - audispd-plugins
  - auditd
  - cracklib-runtime
  - debsums
  - gnupg2
  - haveged
  - libpam-apparmor
  - libpam-modules
  - libpam-pwquality
  - libpam-tmpdir
  - needrestart
  - openssh-server
  - postfix
  - rkhunter
  - rsyslog
  - sysstat
  - tcpd
  - vlock
packages_redhat:
  - aide
  - audispd-plugins
  - audit
  - gnupg2
  - haveged
  - libpwquality
  - openssh-server
  - needrestart
  - postfix
  - psacct
  - rkhunter
  - rsyslog
  - vlock
packages_ubuntu:
  - fwupd
  - secureboot-db
```

`system_upgrade: 'yes'` will run `apt upgrade` or
`dnf update` if required.

Packages to be installed depending of distribution
and packages to be removed (`packages_blocklist`).

### ./defaults/main/password.yml

```yaml
crypto_policy: FIPS
```

Set [cryptographic policies](https://access.redhat.aom/documentation/en-us/red_hat_enterprise_linux/8/html/security_hardening/using-the-system-wide-cryptographic-policies_security-hardening)
if `/etc/crypto-policies/config` exists.

### ./defaults/main/sshd.yml

```yaml
sshd_accept_env: LANG LC_*
sshd_admin_net:
  - 192.168.0.0/24
  - 192.168.1.0/24
sshd_allow_agent_forwarding: 'no'
sshd_allow_groups: sudo
sshd_allow_tcp_forwarding: 'no'
sshd_authentication_methods: any
sshd_banner: /etc/issue.net
sshd_challenge_response_authentication: 'no'
sshd_ciphers: chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr
sshd_client_alive_count_max: 3
sshd_client_alive_interval: 200
sshd_compression: 'no'
sshd_gssapi_authentication: 'no'
sshd_hostbased_authentication: 'no'
sshd_ignore_user_known_hosts: 'yes'
sshd_kerberos_authentication: 'no'
sshd_kex_algorithms: curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256
sshd_log_level: VERBOSE
sshd_login_grace_time: 20
sshd_macs: hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
sshd_max_auth_tries: 3
sshd_max_sessions: 3
sshd_max_startups: 10:30:60
sshd_password_authentication: 'no'
sshd_permit_empty_passwords: 'no'
sshd_permit_root_login: 'no'
sshd_permit_user_environment: 'no'
sshd_port: 22
sshd_print_last_log: 'yes'
sshd_print_motd: 'no'
sshd_rekey_limit: 512M 1h
sshd_strict_modes: 'yes'
sshd_subsystem: sftp internal-sftp
sshd_tcp_keep_alive: 'no'
sshd_use_dns: 'no'
sshd_use_pam: 'yes'
sshd_x11_forwarding: 'no'
```

For a explanation of the options not described below, please read
[https://man.openbsd.org/sshd_config](https://man.openbsd.org/sshd_config).

Only the network(s) defined in `sshd_admin_net` are allowed to
connect to `sshd_port`. Note that additional rules need to be set up in order
to allow access to additional services.

OpenSSH login is allowed only for users whose primary group or supplementary
group list matches one of the patterns in `sshd_allow_groups`.

`sshd_allow_agent_forwarding` specifies whether ssh-agent(1) forwarding is
permitted.

`sshd_allow_tcp_forwarding` specifies whether TCP forwarding is permitted.
The available options are `yes` or all to allow TCP forwarding, `no` to prevent
all TCP forwarding, `local` to allow local (from the perspective of ssh(1))
forwarding only or `remote` to allow remote forwarding only.

`sshd_authentication_methods` specifies the authentication methods that must
be successfully completed in order to grant access to a user.

`sshd_log_level` gives the verbosity level that is used when logging messages.

`sshd_max_auth_tries` and `sshd_max_sessions` specifies the maximum number of
SSH authentication attempts permitted per connection and the maximum number of
open shell, login or subsystem (e.g. sftp) sessions permitted per network
connection.

`sshd_password_authentication` specifies whether password authentication is allowed.

`sshd_port` specifies the port number that sshd(8) listens on.

### ./defaults/main/suid_sgid_blocklist.yml

```yaml
suid_sgid_permissions: true
suid_sgid_blocklist:
  - /bin/awk
  - /bin/base32
  - /bin/base64
  - /bin/bash
  - /bin/busctl
  - /bin/busybox
  - /bin/cat
  - /bin/chage
  - /bin/chmod
  - /bin/chown
  [...]
```

If `suid_sgid_permissions: true` loop through `suid_sgid_blocklist` and remove
any SUID/SGID permissions.

A complete file list is available in
[defaults/main/suid_sgid_blocklist.yml](defaults/main/suid_sgid_blocklist.yml).

### ./defaults/main/sysctl.yml

```yaml
sysctl_dev_tty_ldisc_autoload: 0
sysctl_net_ipv6_conf_accept_ra_rtr_pref: 0
sysctl_settings:
  fs.protected_hardlinks: 1
  fs.protected_symlinks: 1
  fs.suid_dumpable: 0
  kernel.core_uses_pid: 1
  kernel.dmesg_restrict: 1
  kernel.kptr_restrict: 2
  kernel.panic: 60
  kernel.panic_on_oops: 60
  kernel.perf_event_paranoid: 2
  kernel.randomize_va_space: 2
  kernel.sysrq: 0
  kernel.unprivileged_bpf_disabled: 1
  kernel.yama.ptrace_scope: 2
  net.core.bpf_jit_harden: 2
  net.ipv4.conf.all.accept_redirects: 0
  net.ipv4.conf.all.accept_source_route: 0
  net.ipv4.conf.all.log_martians: 1
  net.ipv4.conf.all.rp_filter: 1
  net.ipv4.conf.all.secure_redirects: 0
  net.ipv4.conf.all.send_redirects: 0
  net.ipv4.conf.all.shared_media: 0
  net.ipv4.conf.default.accept_redirects: 0
  net.ipv4.conf.default.accept_source_route: 0
  net.ipv4.conf.default.log_martians: 1
  net.ipv4.conf.default.rp_filter: 1
  net.ipv4.conf.default.secure_redirects: 0
  net.ipv4.conf.default.send_redirects: 0
  net.ipv4.conf.default.shared_media: 0
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
  net.ipv4.tcp_timestamps: 0
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
  net.netfilter.nf_conntrack_max: 2000000
  net.netfilter.nf_conntrack_tcp_loose: 0
```

Configure `sysctl`.

## Recommended Reading

[Center for Internet Security Linux Benchmarks](https://www.cisecurity.org/cis-benchmarks/)

[Common Configuration Enumeration](https://nvd.nist.gov/cce/index.cfm)

[DISA Security Technical Implementation Guides](https://public.cyber.mil/stigs/downloads/?_dl_facet_stigs=operating-systems%2Cunix-linux)

[SCAP Security Guides](https://static.open-scap.org/)

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
