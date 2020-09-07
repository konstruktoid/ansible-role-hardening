# ansible-role-hardening

Ansible role to make a CentOS, Debian, Fedora or Ubuntu server a bit more
secure, [systemd edition](https://freedesktop.org/wiki/Software/systemd/).

Requires [Ansible](https://www.ansible.com/) >= 2.8.

Available on [Ansible Galaxy](https://galaxy.ansible.com/konstruktoid/hardening).

## Distributions Tested using Vagrant

```yaml
bento/debian-10
bento/fedora-31
centos/8
ubuntu/bionic64
ubuntu/focal64
```

## Role Variables with defaults

### auditd

```yaml
auditd_mode: 1
```

Auditd failure mode. 0=silent 1=printk 2=panic.

```yaml
grub_audit_backlog_cmdline: audit_backlog_limit=8192
grub_audit_cmdline: audit=1
```

Enable `auditd` at boot using Grub.

### DNS

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

### Disabled File System kernel modules

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
```

Blocked file system kernel modules.

### File and Process limits

```yaml
limit_nofile_hard: 1024
limit_nofile_soft: 512
limit_nproc_hard: 1024
limit_nproc_soft: 512
```

Maximum number of processes and open files.

### Misc Disabled kernel modules

```yaml
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
```

Blocked kernel modules.

### Disabled Network kernel modules

```yaml
net_modules_blocklist:
  - dccp
  - sctp
  - rds
  - tipc
```

Blocked kernel network modules.

### NTP

```yaml
ntp: 0.ubuntu.pool.ntp.org 1.ubuntu.pool.ntp.org
fallback_ntp: 2.ubuntu.pool.ntp.org 3.ubuntu.pool.ntp.org
```

NTP server host names or IP addresses. [systemd](https://github.com/konstruktoid/hardening/blob/master/systemd.adoc#etcsystemdtimesyncdconf)
option.

### Blocked packages

```yaml
packages_blocklist:
  - apport*
  - autofs
  - avahi*
  - avahi-*
  - beep
  - git
  - pastebinit
  - popularity-contest
  - rsh*
  - rsync
  - talk*
  - telnet*
  - tftp*
  - whoopsie
  - xinetd
  - yp-tools
  - ypbind
```

Packages to be removed.

### Recommended packages

```yaml
packages_debian:
  - acct
  - aide-common
  - apparmor-profiles
  - apparmor-utils
  - audispd-plugins
  - auditd
  - cracklib-runtime
  - debsums
  - gnupg2
  - haveged
  - libpam-apparmor
  - libpam-pwquality
  - libpam-tmpdir
  - needrestart
  - openssh-server
  - postfix
  - rkhunter
  - rsyslog
  - tcpd
  - vlock
```

Packages to be installed on a Debian OS family host.

```yaml
packages_ubuntu:
  - fwupd
  - secureboot-db
```

Packages to be installed on a Ubuntu distribution host.

```yaml
packages_redhat:
  - aide
  - audispd-plugins
  - audit
  - haveged
  - gnugpg2
  - libpam-pwquality
  - openssh-server
  - needrestart
  - postfix
  - psacct
  - rkhunter
  - rsyslog
  - tcp_wrappers
  - vlock
```

Packages to be installed on a RedHat OS family host.

### tcp_challenge_ack_limit kernel configuration

```yaml
random_ack_limit: "{{ 1000000 | random(start=1000) }}"
```

net.ipv4.tcp_challenge_ack_limit, see
[tcp: make challenge acks less predictable](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=75ff39ccc1bd5d3c455b6822ab09e533c551f758).

### Ubuntu reboot

```yaml
reboot_ubuntu: false
```

If true an Ubuntu node will be rebooted if required, using
`pre_reboot_delay: "{{ 3600 | random(start=1) }}"`.

### RedHat RPM keys

```yaml
redhat_rpm_key:
  - 567E347AD0044ADE55BA8A5F199E2F91FD431D51
  - 47DB287789B21722B6D95DDE5326810137017186
```

[Red Hat RPM keys](https://access.redhat.com/security/team/key/)
for use when `ansible_distribution == "RedHat"`.

### OpenSSH daemon configuration

```yaml
sshd_admin_net:
  - 192.168.0.0/24
  - 192.168.1.0/24
sshd_accept_env: LANG LC_*
sshd_allow_agent_forwarding: 'no'
sshd_allow_groups: sudo
sshd_allow_tcp_forwarding: 'no'
sshd_authentication_methods: any
sshd_banner: /etc/issue.net
sshd_challenge_response_authentication: 'no'
sshd_ciphers: chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr
sshd_client_alive_count_max: 0
sshd_client_alive_interval: 300
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

### SUID/SGID binaries

```yaml
suid_sgid_blocklist:
  - /bin/bash
  - /bin/busybox
  - /bin/cat
  - /bin/chmod
  - /bin/chown
  - /bin/cp
  - /bin/dash
  - /bin/date
  - /bin/dd
  - /bin/dmesg
[...]
```

Which binaries that should have SUID/SGID removed, a complete list is available
at <https://github.com/konstruktoid/ansible-role-hardening/blob/master/defaults/main.yml#L112>

## Structure

```sh
.
├── LICENSE
├── README.md
├── Vagrantfile
├── action-lint
│   ├── Dockerfile
│   ├── README.md
│   └── entrypoint.sh
├── defaults
│   └── main.yml
├── handlers
│   └── main.yml
├── meta
│   └── main.yml
├── molecule
│   └── default
│       ├── INSTALL.rst
│       ├── converge.yml
│       ├── molecule.yml
│       └── verify.yml
├── postChecks.sh
├── provision
│   └── setup.sh
├── renovate.json
├── runPlaybook.sh
├── tasks
│   ├── adduser.yml
│   ├── aide.yml
│   ├── apparmor.yml
│   ├── apport.yml
│   ├── auditd.yml
│   ├── cron.yml
│   ├── ctrlaltdel.yml
│   ├── disablefs.yml
│   ├── disablemod.yml
│   ├── disablenet.yml
│   ├── extras.yml
│   ├── firewall.yml
│   ├── fstab.yml
│   ├── hosts.yml
│   ├── issue.yml
│   ├── journalconf.yml
│   ├── limits.yml
│   ├── lockroot.yml
│   ├── logindconf.yml
│   ├── logindefs.yml
│   ├── main.yml
│   ├── motdnews.yml
│   ├── mount.yml
│   ├── packages.yml
│   ├── password.yml
│   ├── path.yml
│   ├── pkgupdate.yml
│   ├── postfix.yml
│   ├── pre.yml
│   ├── prelink.yml
│   ├── resolvedconf.yml
│   ├── rkhunter.yml
│   ├── rootaccess.yml
│   ├── sshdconfig.yml
│   ├── sudo.yml
│   ├── suid.yml
│   ├── sysctl.yml
│   ├── systemdconf.yml
│   ├── timesyncd.yml
│   ├── umask.yml
│   └── users.yml
├── templates
│   ├── etc
│   │   ├── adduser.conf.j2
│   │   ├── ansible
│   │   │   └── facts.d
│   │   │       ├── cpuinfo.fact
│   │   │       ├── reboot.fact
│   │   │       ├── sshkeys.fact
│   │   │       └── systemd.fact
│   │   ├── apt
│   │   │   └── apt.conf.d
│   │   │       └── 99noexec-tmp.j2
│   │   ├── audit
│   │   │   └── rules.d
│   │   │       └── hardening.rules.j2
│   │   ├── default
│   │   │   ├── rkhunter.j2
│   │   │   └── useradd.j2
│   │   ├── hosts.allow.j2
│   │   ├── hosts.deny.j2
│   │   ├── issue.j2
│   │   ├── login.defs.j2
│   │   ├── logrotate.conf.j2
│   │   ├── pam.d
│   │   │   ├── common-account.j2
│   │   │   ├── common-auth.j2
│   │   │   ├── common-password.j2
│   │   │   └── login.j2
│   │   ├── profile.d
│   │   │   └── initpath.sh.j2
│   │   ├── securetty.j2
│   │   ├── security
│   │   │   ├── access.conf.j2
│   │   │   ├── limits.conf.j2
│   │   │   └── pwquality.conf.j2
│   │   ├── ssh
│   │   │   └── sshd_config.j2
│   │   ├── sysctl.conf.j2
│   │   └── systemd
│   │       ├── coredump.conf.j2
│   │       ├── journald.conf.j2
│   │       ├── logind.conf.j2
│   │       ├── resolved.conf.j2
│   │       ├── system.conf.j2
│   │       ├── timesyncd.conf.j2
│   │       ├── tmp.mount.j2
│   │       └── user.conf.j2
│   └── lib
│       └── systemd
│           └── system
│               ├── aidecheck.service.j2
│               └── aidecheck.timer.j2
└── tests
    ├── debug_facts.yml
    ├── inventory
    └── test.yml

26 directories, 96 files
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

## Testing

```shell
ansible-playbook tests/test.yml --extra-vars "sshd_admin_net=192.168.1.0/24" \
  -c local -i 'localhost,' -K
```

The repository contains a [Vagrant](https://www.vagrantup.com/ "Vagrant")
configuration file, which will run the `konstruktoid.hardening` role.

The [runPlaybook.sh](runPlaybook.sh) script may be used to automatically update
and run the role on all configured Vagrant boxes. After the role has been
applied, [Lynis](https://github.com/CISOFy/lynis) and various [bats tests](https://github.com/konstruktoid/hardening/tree/master/tests)
will be downloaded and the configurationen tested.

To run a [OpenSCAP](https://github.com/ComplianceAsCode/content) test on a
Fedora host using the included Vagrantfile follow the instructions on
[https://copr.fedorainfracloud.org/coprs/openscapmaint/openscap-latest/](https://copr.fedorainfracloud.org/coprs/openscapmaint/openscap-latest/).

```shell
curl -SsL http://copr.fedoraproject.org/coprs/openscapmaint/openscap-latest/repo/epel-7/openscapmaint-openscap-latest-epel-7.repo | \
  sudo tee -a /etc/yum.repos.d/openscapmaint-openscap-latest-epel-7.repo
sudo dnf install -y openscap-scanner scap-security-guide
oscap info --fetch-remote-resources /usr/share/xml/scap/ssg/content/ssg-fedora-ds.xml
sudo oscap xccdf eval --fetch-remote-resources \
  --profile xccdf_org.ssgproject.content_profile_pci-dss \
  --report fedora_pci-report.html /usr/share/xml/scap/ssg/content/ssg-fedora-ds.xml
```

To run a [OpenSCAP](https://github.com/ComplianceAsCode/content) test on a
Ubuntu 18.04 host, where `v0.1.50` should be replaced with the latest available
version:

```shell
sudo apt-get -y install libopenscap8 unzip
wget https://github.com/ComplianceAsCode/content/releases/download/v0.1.50/scap-security-guide-0.1.50.zip
unzip scap-security-guide-0.1.50.zip
cd scap-security-guide-0.1.50
oscap info --fetch-remote-resources ./ssg-ubuntu1804-ds.xml
sudo oscap xccdf eval --fetch-remote-resources \
  --profile xccdf_org.ssgproject.content_profile_anssi_np_nt28_high \
  --report ../bionic_anssi-report.html ./ssg-ubuntu1804-ds.xml
```

## Recommended Reading

[CIS Distribution Independent Linux Benchmark v1.0.0](https://www.cisecurity.org/cis-benchmarks/)

[Common Configuration Enumeration](https://nvd.nist.gov/cce/index.cfm)

[Canonical Ubuntu 16.04 LTS STIG - Ver 1, Rel 2](https://public.cyber.mil/stigs/downloads/?_dl_facet_stigs=operating-systems%2Cunix-linux)

[Guide to the Secure Configuration of Red Hat Enterprise Linux 8](https://static.open-scap.org/ssg-guides/ssg-rhel8-guide-default.html)

[Red Hat Enterprise Linux 7 - Ver 2, Rel 3 STIG](https://public.cyber.mil/stigs/downloads/?_dl_facet_stigs=operating-systems%2Cunix-linux)

[Security focused systemd configuration](https://github.com/konstruktoid/hardening/blob/master/systemd.adoc)

## Contributing

Do you want to contribute? That's great! Contributions are always welcome,
no matter how large or small. If you found something odd, feel free to submit a
issue, improve the code by creating a pull request, or by
[sponsoring this project](https://github.com/sponsors/konstruktoid).

## License

Apache License Version 2.0

## Author Information

[https://github.com/konstruktoid](https://github.com/konstruktoid "github.com/konstruktoid")
