ansible-role-hardening
=========

Ansible role to make a Ubuntu or CentoOS 7 server a bit more secure, systemd edition.

Role Variables
--------------

    auditd_arch: b64
Architecture to use with auditd. Use `getconf LONG_BIT`.

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

    fallback_dns: 8.8.8.8 8.8.4.4
IPv4 and IPv6 addresses to use as the fallback DNS servers. [systemd](https://github.com/konstruktoid/hardening/blob/master/systemd.adoc#etcsystemdresolvedconf) option.

    dnssec: allow-downgrade
If set to "allow-downgrade" DNSSEC validation is attempted, but if the server does not support DNSSEC properly, DNSSEC mode is automatically disabled. [systemd](https://github.com/konstruktoid/hardening/blob/master/systemd.adoc#etcsystemdresolvedconf) option.

    suid_sgid_blacklist: [/bin/ntfs-3g, /usr/bin/at, /bin/fusermount, /bin/mount, /bin/ping, /bin/ping6, /bin/su, /bin/umount, /sbin/mount.nfs, /usr/bin/bsd-write, /usr/bin/chage, /usr/bin/chfn, /usr/bin/chsh, /usr/bin/mlocate, /usr/bin/mtr, /usr/bin/newgrp, /usr/bin/pkexec, /usr/bin/traceroute6.iputils, /usr/bin/wall, /usr/bin/write, /usr/sbin/pppd]
Which binaries that should have SUID/SGID removed.

    random_ack_limit: "{{ 1000000 | random(start=1000) }}"
net.ipv4.tcp_challenge_ack_limit, see [tcp: make challenge acks less predictable](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=75ff39ccc1bd5d3c455b6822ab09e533c551f758).

    packages_ubuntu: [acct, aide-common, apparmor-profiles, apparmor-utils, auditd, debsums, haveged, libpam-cracklib, libpam-tmpdir, openssh-server, rkhunter, rsyslog]
Packages to be installed on a Ubuntu host.

    packages_centos: [aide, audit, haveged, openssh-server, rkhunter, rsyslog]
Packages to be installed on a CentOS host.

    packages_blacklist: [avahi-*, rsh*, talk*, telnet*, tftp*, yp-tools, ypbind, xinetd]
Packages to be removed.

    net_modules_blacklist: [dccp, sctp, rds, tipc]
Blacklisted kernel modules.

    fs_modules_blacklist: [cramfs, freevxfs, hfs, hfsplus, jffs2, squashfs, udf, vfat]
Blacklisted kernel modules.

    misc_modules_blacklist: [bluetooth, firewire-core, net-pf-31, soundcore, thunderbolt, usb-midi, usb-storage]
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
Additional Grub options, currently only `ansible_distribution == "Ubuntu"`

Templates
---------

The CCE identifiers are taken from [Secure Configuration of Red Hat Enterprise Linux 7](https://people.redhat.com/swells/scap-security-guide/RHEL/7/output/table-rhel7-cces.html)
since there currently are [no complete list of identifiers for CentOS or Ubuntu](https://static.open-scap.org/).

[CIS identifiers](https://benchmarks.cisecurity.org/downloads/show-single/index.cfm?file=independentlinux.100) will be added in the future.

```shell
templates/etc/security/access.conf.j2
templates/etc/adduser.conf.j2
templates/lib/systemd/system/aidecheck.service.j2
templates/lib/systemd/system/aidecheck.timer.j2
templates/etc/audit/rules.d/hardening.rules.j2
templates/etc/pam.d/common-account.j2
templates/etc/pam.d/common-auth.j2
templates/etc/pam.d/common-password.j2
templates/etc/systemd/coredump.conf.j2
templates/etc/hosts.allow.j2
templates/etc/hosts.deny.j2
templates/etc/profile.d/initpath.sh.j2
templates/etc/issue.j2
templates/etc/systemd/journald.conf.j2
templates/etc/security/limits.conf.j2
templates/etc/login.defs.j2
templates/etc/pam.d/login.j2
templates/etc/systemd/logind.conf.j2
templates/etc/logrotate.conf.j2
templates/etc/security/pwquality.conf.j2
templates/etc/systemd/resolved.conf.j2
templates/etc/default/rkhunter.j2
templates/etc/securetty.j2
templates/etc/ssh/sshd_config.j2
templates/etc/sysctl.conf.j2
templates/etc/systemd/system.conf.j2
templates/etc/systemd/timesyncd.conf.j2
templates/etc/systemd/user.conf.j2
templates/etc/default/useradd.j2
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
sudo oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_stig-rhel7-server-upstream --results-arf centos7_stig-arf.xml --report centos7_stig-report.html /usr/share/xml/scap/ssg/content/ssg-centos7-ds.xml
```

Please note that the [OpenSCAP Evaluation Report](centos7_stig-report.html)
contains multiple false negatives, specially in the "System Accounting with
auditd" section, and it doesn't take `systemd` configuration into
account at all.

```shell
for a in adjtimex settimeofday clock_settime fchmod fremovexattr EACCES EPERM ; do sudo auditctl -l | grep $a; done
-a always,exit -F arch=b64 -S adjtimex -F key=audit_time_rules
-a always,exit -F arch=b64 -S settimeofday -F key=audit_time_rules
-a always,exit -F arch=b64 -S clock_settime -F key=audit_time_rules
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_mod
-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=-1 -F key=perm_mod
-a always,exit -F arch=b64 -S open,truncate,ftruncate,creat,openat,open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=-1 -F key=access
-a always,exit -F arch=b64 -S open,truncate,ftruncate,creat,openat,open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=-1 -F key=access
```

Recommended Reading
-------------------

[CCE Identifiers in Guide to the Secure Configuration of Red Hat Enterprise Linux 7](https://people.redhat.com/swells/scap-security-guide/RHEL/7/output/table-rhel7-cces.html)

[CIS Distribution Independent Linux Benchmark v1.0.0](https://benchmarks.cisecurity.org/downloads/show-single/index.cfm?file=independentlinux.100)

[Common Configuration Enumeration](https://nvd.nist.gov/cce/index.cfm)

[Draft Red Hat 7 STIG Version 1, Release 0.1](http://iase.disa.mil/stigs/os/unix-linux/Pages/index.aspx)

[Rules with PCI DSS Reference in Guide to the Secure Configuration of Red Hat Enterprise Linux 7](https://people.redhat.com/swells/scap-security-guide/RHEL/7/output/table-rhel7-pcidss.html)

[Security focused systemd configuration](https://github.com/konstruktoid/hardening/blob/master/systemd.adoc)

License
-------

Apache License Version 2.0

Author Information
------------------

[https://github.com/konstruktoid](https://github.com/konstruktoid "github.com/konstruktoid")
