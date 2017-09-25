ansible-role-hardening
=========

Ansible role to make a Debian, Ubuntu or CentoOS 7 server a bit more secure, systemd edition.

Requires [Ansible](https://www.ansible.com/) >= 2.2.

Distributions Tested
--------------------

```
 centos/7
 debian/jessie64
 fedora/26-cloud-base (FAILS)
 ubuntu/artful64
 ubuntu/xenial64
 ubuntu/yakkety64
 ubuntu/zesty64
```

Role Variables
--------------

    redhat_rpm_key: [567E347AD0044ADE55BA8A5F199E2F91FD431D51, 47DB287789B21722B6D95DDE5326810137017186]
[Red Hat RPM keys](https://access.redhat.com/security/team/key/) for use when `ansible_distribution == "RedHat"`.

    ntp: 0.ubuntu.pool.ntp.org 1.ubuntu.pool.ntp.org
NTP server host names or IP addresses. [systemd](https://github.com/konstruktoid/hardening/blob/master/systemd.adoc#etcsystemdtimesyncdconf) option.

    fallback_ntp: 2.ubuntu.pool.ntp.org 3.ubuntu.pool.ntp.org
NTP server host names or IP addresses to be used as the fallback NTP servers. [systemd](https://github.com/konstruktoid/hardening/blob/master/systemd.adoc#etcsystemdtimesyncdconf) option.

    ssh_allow_groups: sudo
OpenSSH login is allowed only for users whose primary group or supplementary group list matches one of the patterns.

    sshd_admin_net: [192.168.0.0/24, 192.168.1.0/24]
By default only the network(s) defined here are allowed to connect to the host using port 22. Note that additional rules need to be set up in order to allow access to additional services.

    dns: 127.0.0.1
IPv4 and IPv6 addresses to use as system DNS servers. [systemd](https://github.com/konstruktoid/hardening/blob/master/systemd.adoc#etcsystemdresolvedconf) option.

    fallback_dns: 185.121.177.177 130.255.73.90
IPv4 and IPv6 addresses to use as the fallback DNS servers. [systemd](https://github.com/konstruktoid/hardening/blob/master/systemd.adoc#etcsystemdresolvedconf) option.

    dnssec: allow-downgrade
If set to "allow-downgrade" DNSSEC validation is attempted, but if the server does not support DNSSEC properly, DNSSEC mode is automatically disabled. [systemd](https://github.com/konstruktoid/hardening/blob/master/systemd.adoc#etcsystemdresolvedconf) option.

    suid_sgid_blacklist: [/bin/ntfs-3g, /usr/bin/at, /bin/fusermount, /bin/mount, /bin/ping, /bin/ping6, /bin/su, /bin/umount, /sbin/mount.nfs, /usr/bin/bsd-write, /usr/bin/chage, /usr/bin/chfn, /usr/bin/chsh, /usr/bin/mlocate, /usr/bin/mtr, /usr/bin/newgrp, /usr/bin/pkexec, /usr/bin/traceroute6.iputils, /usr/bin/wall, /usr/bin/write, /usr/sbin/pppd]
Which binaries that should have SUID/SGID removed.

    random_ack_limit: "{{ 1000000 | random(start=1000) }}"
net.ipv4.tcp_challenge_ack_limit, see [tcp: make challenge acks less predictable](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=75ff39ccc1bd5d3c455b6822ab09e533c551f758).

    packages_debian: [acct, aide-common, apparmor-profiles, apparmor-utils, auditd, debsums, haveged, libpam-cracklib, libpam-tmpdir, openssh-server, rkhunter, rsyslog, vlock]
Packages to be installed on a Ubuntu host.

    packages_redhat: [aide, audit, haveged, openssh-server, rkhunter, rsyslog, vlock]
Packages to be installed on a CentOS host.

    packages_blacklist: [avahi-*, rsh*, talk*, telnet*, tftp*, yp-tools, ypbind, xinetd]
Packages to be removed.

    net_modules_blacklist: [dccp, sctp, rds, tipc]
Blacklisted kernel modules.

    fs_modules_blacklist: [cramfs, freevxfs, hfs, hfsplus, jffs2, squashfs, udf, vfat]
Blacklisted kernel modules.

    misc_modules_blacklist: [bluetooth, bnep, btusb, firewire-core, n_hdlc, net-pf-31, soundcore, thunderbolt, usb-midi, usb-storage]
Blacklisted kernel modules.

    limit_nofile_soft: 100
Maximum number of open files. Soft limit.

    limit_nofile_hard: 150
Maximum number of open files. Hard limit.

    limit_nproc_soft: 100
Maximum number of processes. Soft limit.

    limit_nproc_hard: 150
Maximum number of processes. Hard limit.

    grub_cmdline: audit=1
Additional Grub options, currently only `ansible_os_family == "Debian"`

Templates
---------

The CCE identifiers are taken from [CCE Identifiers in Guide to the Secure Configuration of Red Hat Enterprise Linux 7](https://people.redhat.com/swells/scap-security-guide/tables/table-rhel7-cces.html) since there currently are [no complete list of identifiers for CentOS or Ubuntu](https://static.open-scap.org/).

[CIS identifiers](https://benchmarks.cisecurity.org/downloads/show-single/index.cfm?file=independentlinux.100) will be added in the future.

```sh
templates/
├── etc
│   ├── adduser.conf.j2
│   ├── audit
│   │   └── rules.d
│   │       └── hardening.rules.j2
│   ├── default
│   │   ├── rkhunter.j2
│   │   └── useradd.j2
│   ├── hosts.allow.j2
│   ├── hosts.deny.j2
│   ├── issue.j2
│   ├── login.defs.j2
│   ├── logrotate.conf.j2
│   ├── pam.d
│   │   ├── common-account.j2
│   │   ├── common-auth.j2
│   │   ├── common-password.j2
│   │   └── login.j2
│   ├── profile.d
│   │   └── initpath.sh.j2
│   ├── securetty.j2
│   ├── security
│   │   ├── access.conf.j2
│   │   ├── limits.conf.j2
│   │   └── pwquality.conf.j2
│   ├── ssh
│   │   └── sshd_config.j2
│   ├── sysctl.conf.j2
│   └── systemd
│       ├── coredump.conf.j2
│       ├── journald.conf.j2
│       ├── logind.conf.j2
│       ├── resolved.conf.j2
│       ├── system.conf.j2
│       ├── timesyncd.conf.j2
│       └── user.conf.j2
└── lib
    └── systemd
        └── system
            ├── aidecheck.service.j2
            └── aidecheck.timer.j2
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
configuration file, which will run the `konstruktoid.hardening` role.

OpenSCAP test on a CentOS 7 host using the included Vagrantfile:

```shell
sudo yum install -y openscap-scanner scap-security-guide
sudo oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_stig-rhel7-disa --results-arf centos7_stig-arf.xml --report centos7_stig-report.html /usr/share/xml/scap/ssg/content/ssg-centos7-ds.xml
```

Recommended Reading
-------------------

[Rules In DISA STIG for Red Hat Enterprise Linux 7](https://people.redhat.com/swells/scap-security-guide/tables/table-rhel7-stig.html)

[CIS Distribution Independent Linux Benchmark v1.0.0](https://benchmarks.cisecurity.org/downloads/show-single/index.cfm?file=independentlinux.100)

[Common Configuration Enumeration](https://nvd.nist.gov/cce/index.cfm)

[Draft Red Hat 7 STIG Version 1, Release 0.1](http://iase.disa.mil/stigs/os/unix-linux/Pages/index.aspx)

[Security focused systemd configuration](https://github.com/konstruktoid/hardening/blob/master/systemd.adoc)

License
-------

Apache License Version 2.0

Author Information
------------------

[https://github.com/konstruktoid](https://github.com/konstruktoid "github.com/konstruktoid")
