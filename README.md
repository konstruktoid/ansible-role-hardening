ansible-role-hardening
=========

Ansible role to make a Ubuntu or CentoOS 7 server a bit more secure.

Role Variables
--------------

Current role variables, along with default values:

```shell
ntp: 0.ubuntu.pool.ntp.org 1.ubuntu.pool.ntp.org
fallback_ntp: 2.ubuntu.pool.ntp.org 3.ubuntu.pool.ntp.org
ssh_allow_groups: sudo
sshd_admin_net: [192.168.0.0/24, 192.168.1.0/24]
dns: 127.0.0.1
fallback_dns: 8.8.8.8 8.8.4.4
dnssec: allow-downgrade
suid_sgid_blacklist: [/bin/fusermount, /bin/mount, /bin/ping, /bin/ping6, /bin/su, /bin/umount, /sbin/mount.nfs, /usr/bin/bsd-write, /usr/bin/chage, /usr/bin/chfn, /usr/bin/chsh, /usr/bin/mlocate, /usr/bin/mtr, /usr/bin/newgrp, /usr/bin/pkexec, /usr/bin/traceroute6.iputils, /usr/bin/wall, /usr/sbin/pppd]
random_ack_limit: "{{ 1000000 | random(start=1000) }}"
packages_ubuntu: [acct, aide-common, apparmor-profiles, apparmor-utils, auditd, debsums, haveged, libpam-cracklib, libpam-tmpdir, openssh-server, rkhunter, rsyslog]
packages_centos: [aide, audit, haveged, openssh-server, rkhunter, rsyslog]
packages_blacklist: [avahi-*, rsh*, talk*, telnet*, tftp*, yp-tools, ypbind, xinetd]
net_modules_blacklist: [dccp, sctp, rds, tipc]
fs_modules_blacklist: [cramfs, freevxfs, hfs, hfsplus, jffs2, squashfs, udf, vfat]
misc_modules_blacklist: [bluetooth, firewire-core, net-pf-31, soundcore, thunderbolt, usb-midi, usb-storage]
limit_nofile_soft: 100
limit_nofile_hard: 150
limit_nproc_soft: 100
limit_nproc_hard: 150
```

Templates:

```shell
templates/access.conf.j2
templates/adduser.conf.j2
templates/aidecheck.service.j2
templates/aidecheck.timer.j2
templates/audit.rules.j2
templates/common-account.j2
templates/common-auth.j2
templates/common-password.j2
templates/coredump.conf.j2
templates/hosts.allow.j2
templates/hosts.deny.j2
templates/initpath.sh.j2
templates/issue.j2
templates/journald.conf.j2
templates/limits.conf.j2
templates/login.defs.j2
templates/login.j2
templates/logind.conf.j2
templates/logrotate.conf.j2
templates/pwquality.conf.j2
templates/resolved.conf.j2
templates/rkhunter.j2
templates/securetty.j2
templates/sshd_config.j2
templates/sysctl.conf.j2
templates/system.conf.j2
templates/timesyncd.conf.j2
templates/user.conf.j2
templates/useradd.j2
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

The repository contains a [Vagrant](https://www.vagrantup.com/ "Vagrant")
configuration file, which will run the `konstruktoid.hardening` role.

Recommended Reading
-------------------

[Rules with PCI DSS Reference in Guide to the Secure Configuration of Red Hat Enterprise Linux 7](https://people.redhat.com/swells/scap-security-guide/RHEL/7/output/table-rhel7-pcidss.html)

[CCE Identifiers in Guide to the Secure Configuration of Red Hat Enterprise Linux 7](https://people.redhat.com/swells/scap-security-guide/RHEL/7/output/table-rhel7-cces.html)

[CIS Distribution Independent Linux Benchmark v1.0.0](https://benchmarks.cisecurity.org/downloads/show-single/index.cfm?file=independentlinux.100)

[Draft Red Hat 7 STIG Version 1, Release 0.1](http://iase.disa.mil/stigs/os/unix-linux/Pages/index.aspx)

[Security focused systemd configuration](https://github.com/konstruktoid/hardening/blob/master/systemd.adoc)

License
-------

Apache License Version 2.0

Author Information
------------------

[https://github.com/konstruktoid](https://github.com/konstruktoid "github.com/konstruktoid")

