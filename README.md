ansible-role-hardening
=========

Ansible role to make a Debian, Ubuntu or CentoOS server a bit more secure, systemd edition.

Requires [Ansible](https://www.ansible.com/) >= 2.7.

Distributions Tested using Vagrant
--------------------

```
bento/centos-8
bento/debian-10
bento/fedora-30
ubuntu/bionic64
ubuntu/disco64
ubuntu/eoan64
```

Role Variables
--------------

    redhat_rpm_key: [567E347AD0044ADE55BA8A5F199E2F91FD431D51, 47DB287789B21722B6D95DDE5326810137017186]
[Red Hat RPM keys](https://access.redhat.com/security/team/key/) for use when `ansible_distribution == "RedHat"`.

    ntp: 0.ubuntu.pool.ntp.org 1.ubuntu.pool.ntp.org
NTP server host names or IP addresses. [systemd](https://github.com/konstruktoid/hardening/blob/master/systemd.adoc#etcsystemdtimesyncdconf) option.

    fallback_ntp: 2.ubuntu.pool.ntp.org 3.ubuntu.pool.ntp.org
NTP server host names or IP addresses to be used as the fallback NTP servers. [systemd](https://github.com/konstruktoid/hardening/blob/master/systemd.adoc#etcsystemdtimesyncdconf) option.

    sshd_allow_groups: sudo
OpenSSH login is allowed only for users whose primary group or supplementary group list matches one of the patterns.

    sshd_port: 22
Specifies the port number that sshd(8) listens on.

    sshd_admin_net: [192.168.0.0/24, 192.168.1.0/24]
By default only the network(s) defined here are allowed to connect to the host using port 22. Note that additional rules need to be set up in order to allow access to additional services.

    sshd_max_auth_tries: 2
Specifies the maximum number of SSH authentication attempts permitted per connection.

    sshd_max_sessions: 2
Specifies the maximum number of open shell, login or subsystem (e.g. sftp) sessions permitted per network connection.

    dns: 127.0.0.1
IPv4 and IPv6 addresses to use as system DNS servers. [systemd](https://github.com/konstruktoid/hardening/blob/master/systemd.adoc#etcsystemdresolvedconf) option.

    fallback_dns: 1.1.1.1 9.9.9.9
IPv4 and IPv6 addresses to use as the fallback DNS servers. [systemd](https://github.com/konstruktoid/hardening/blob/master/systemd.adoc#etcsystemdresolvedconf) option.

    dnssec: allow-downgrade
If set to "allow-downgrade" DNSSEC validation is attempted, but if the server does not support DNSSEC properly, DNSSEC mode is automatically disabled. [systemd](https://github.com/konstruktoid/hardening/blob/master/systemd.adoc#etcsystemdresolvedconf) option.

    suid_sgid_blacklist: [/bin/ntfs-3g, /usr/bin/at, /bin/fusermount, /bin/mount, /bin/ping, /bin/ping6, /bin/su, /bin/umount, /sbin/mount.nfs, /usr/bin/bsd-write, /usr/bin/chage, /usr/bin/chfn, /usr/bin/chsh, /usr/bin/mlocate, /usr/bin/mtr, /usr/bin/newgrp, /usr/bin/pkexec, /usr/bin/traceroute6.iputils, /usr/bin/wall, /usr/bin/write, /usr/sbin/pppd]
Which binaries that should have SUID/SGID removed.

    random_ack_limit: "{{ 1000000 | random(start=1000) }}"
net.ipv4.tcp_challenge_ack_limit, see [tcp: make challenge acks less predictable](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=75ff39ccc1bd5d3c455b6822ab09e533c551f758).

    packages_debian: [acct, aide-common, apparmor-profiles, apparmor-utils, auditd, debsums, haveged, libpam-apparmor, libpam-cracklib, libpam-tmpdir, needrestart, openssh-server, postfix, rkhunter, rsyslog, tcpd, vlock]
Packages to be installed on a Ubuntu or Debian host.

    packages_redhat: [aide, audit, haveged, openssh-server, needrestart, postfix, psacct, rkhunter, rsyslog, tcp_wrappers, vlock]
Packages to be installed on a RedHat host.

    packages_blacklist: [apport*, avahi*, avahi-*, beep, git, pastebinit, popularity-contest, rsh*, talk*, telnet*, tftp*, whoopsie, xinetd, yp-tools, ypbind]
Packages to be removed.

    net_modules_blacklist: [dccp, sctp, rds, tipc]
Blacklisted kernel modules.

    fs_modules_blacklist: [cramfs, freevxfs, hfs, hfsplus, jffs2, squashfs, udf, vfat]
Blacklisted kernel modules.

    misc_modules_blacklist: [bluetooth, bnep, btusb, firewire-core, floppy, n_hdlc, net-pf-31, pcspkr, soundcore, thunderbolt, usb-midi, usb-storage]
Blacklisted kernel modules.

    limit_nofile_soft: 512
Maximum number of open files. Soft limit.

    limit_nofile_hard: 1024
Maximum number of open files. Hard limit.

    limit_nproc_soft: 512
Maximum number of processes. Soft limit.

    limit_nproc_hard: 1024
Maximum number of processes. Hard limit.

    grub_cmdline: audit=1 audit_backlog_limit=8192
Additional Grub options, currently only `ansible_os_family == "Debian"`

    auditd_mode: 1
Auditd failure mode. 0=silent 1=printk 2=panic.

    reboot_ubuntu: false
If true an Ubuntu node will be rebooted if required. `pre_reboot_delay: "{{ 3600 | random(start=1) }}"`.

Templates
---------

The CCE identifiers are taken from [CCE Identifiers in Guide to the Secure Configuration of Red Hat Enterprise Linux 7](https://people.redhat.com/swells/scap-security-guide/tables/table-rhel7-cces.html) since there currently are [no complete list of identifiers for CentOS or Ubuntu](https://static.open-scap.org/).

[CIS identifiers](https://benchmarks.cisecurity.org/downloads/show-single/index.cfm?file=independentlinux.100) will be added in the future.

Structure
---------

```sh
.
├── LICENSE
├── README.md
├── Vagrantfile
├── action-lint
│   ├── Dockerfile
│   ├── README.md
│   └── entrypoint.sh
├── checkScore.sh
├── defaults
│   └── main.yml
├── handlers
│   └── main.yml
├── meta
│   └── main.yml
├── provision
│   └── setup.sh
├── renovate.json
├── runPlaybook.sh
├── tasks
│   ├── 01_pre.yml
│   ├── 02_firewall.yml
│   ├── 03_disablenet.yml
│   ├── 04_disablefs.yml
│   ├── 05_systemdconf.yml
│   ├── 06_journalconf.yml
│   ├── 07_timesyncd.yml
│   ├── 08_fstab.yml
│   ├── 09_prelink.yml
│   ├── 10_pkgupdate.yml
│   ├── 11_hosts.yml
│   ├── 12_logindefs.yml
│   ├── 13_sysctl.yml
│   ├── 14_limits.yml
│   ├── 15_adduser.yml
│   ├── 16_rootaccess.yml
│   ├── 17_packages.yml
│   ├── 18_sshdconfig.yml
│   ├── 19_password.yml
│   ├── 20_cron.yml
│   ├── 21_ctrlaltdel.yml
│   ├── 22_auditd.yml
│   ├── 23_disablemod.yml
│   ├── 24_aide.yml
│   ├── 26_users.yml
│   ├── 27_suid.yml
│   ├── 28_umask.yml
│   ├── 30_path.yml
│   ├── 31_logindconf.yml
│   ├── 32_resolvedconf.yml
│   ├── 33_rkhunter.yml
│   ├── 34_issue.yml
│   ├── 35_apport.yml
│   ├── 36_lockroot.yml
│   ├── 37_mount.yml
│   ├── 38_postfix.yml
│   ├── 39_motdnews.yml
│   ├── 99_extras.yml
│   └── main.yml
├── templates
│   ├── etc
│   │   ├── adduser.conf.j2
│   │   ├── ansible
│   │   │   └── facts.d
│   │   │       ├── cpuinfo_rdrand.fact
│   │   │       └── systemd_version.fact
│   │   ├── apt
│   │   │   └── apt.conf.d
│   │   │       └── 99noexec-tmp.j2
│   │   ├── audit
│   │   │   └── rules.d
│   │   │       └── hardening.rules.j2
│   │   ├── default
│   │   │   ├── rkhunter.j2
│   │   │   └── useradd.j2
│   │   ├── hosts.allow.j2
│   │   ├── hosts.deny.j2
│   │   ├── issue.j2
│   │   ├── login.defs.j2
│   │   ├── logrotate.conf.j2
│   │   ├── pam.d
│   │   │   ├── common-account.j2
│   │   │   ├── common-auth.j2
│   │   │   ├── common-password.j2
│   │   │   └── login.j2
│   │   ├── profile.d
│   │   │   └── initpath.sh.j2
│   │   ├── securetty.j2
│   │   ├── security
│   │   │   ├── access.conf.j2
│   │   │   ├── limits.conf.j2
│   │   │   └── pwquality.conf.j2
│   │   ├── ssh
│   │   │   └── sshd_config.j2
│   │   ├── sysctl.conf.j2
│   │   └── systemd
│   │       ├── coredump.conf.j2
│   │       ├── journald.conf.j2
│   │       ├── logind.conf.j2
│   │       ├── resolved.conf.j2
│   │       ├── system.conf.j2
│   │       ├── timesyncd.conf.j2
│   │       ├── tmp.mount.j2
│   │       └── user.conf.j2
│   └── lib
│       └── systemd
│           └── system
│               ├── aidecheck.service.j2
│               └── aidecheck.timer.j2
└── tests
    ├── inventory
    ├── test.retry
    └── test.yml
```

Dependencies
------------

None.

Example Playbook
----------------

```shell
---
- hosts: all
  serial: 50%
    - { role: konstruktoid.hardening, sshd_admin_net: [10.0.0.0/24] }
...
```

Testing
-------

```shell
ansible-playbook tests/test.yml --extra-vars "sshd_admin_net=192.168.1.0/24" -c local -i 'localhost,' -K
```

The repository contains a [Vagrant](https://www.vagrantup.com/ "Vagrant")
configuration file, which will run the `konstruktoid.hardening` role. The
[runPlaybook.sh](runPlaybook.sh) script may be used to automatically update and
run the role on all configured Vagrant boxes.

[OpenSCAP](https://github.com/ComplianceAsCode/content) test on a CentOS 8 host using the included Vagrantfile:

```shell
sudo wget http://copr.fedoraproject.org/coprs/openscapmaint/openscap-latest/repo/epel-7/openscapmaint-openscap-latest-epel-7.repo -O /etc/yum.repos.d/openscapmaint-openscap-latest-epel-7.repo
sudo yum install -y openscap-scanner scap-security-guide
oscap info --fetch-remote-resources /usr/share/xml/scap/ssg/content/ssg-centos8-ds.xml
sudo oscap xccdf eval --fetch-remote-resources --profile xccdf_org.ssgproject.content_profile_standard --report centos8_stig-report.html /usr/share/xml/scap/ssg/content/ssg-centos8-ds.xml
```

Recommended Reading
-------------------

[Rules In DISA STIG for Red Hat Enterprise Linux 7](https://people.redhat.com/swells/scap-security-guide/tables/table-rhel7-stig.html)

[CIS Distribution Independent Linux Benchmark v1.0.0](https://www.cisecurity.org/cis-benchmarks/)

[Common Configuration Enumeration](https://nvd.nist.gov/cce/index.cfm)

[Canonical Ubuntu 16.04 LTS STIG - Ver 1, Rel 2](https://public.cyber.mil/stigs/downloads/?_dl_facet_stigs=operating-systems%2Cunix-linux)

[Red Hat Enterprise Linux 7 - Ver 2, Rel 3 STIG](https://public.cyber.mil/stigs/downloads/?_dl_facet_stigs=operating-systems%2Cunix-linux)

[Security focused systemd configuration](https://github.com/konstruktoid/hardening/blob/master/systemd.adoc)

License
-------

Apache License Version 2.0

Author Information
------------------

[https://github.com/konstruktoid](https://github.com/konstruktoid "github.com/konstruktoid")
