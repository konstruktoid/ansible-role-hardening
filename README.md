ansible-role-hardening
=========

Ansible role to make a Ubuntu server a bit more secure.

Role Variables
--------------

Current role variables, along with default values:

```
ntp: 0.ubuntu.pool.ntp.org 1.ubuntu.pool.ntp.org
fallback_ntp: 2.ubuntu.pool.ntp.org 3.ubuntu.pool.ntp.org
ssh_allow_groups: sudo
sshd_admin_net: [192.168.0.0/24, 192.168.1.0/24]
dns: 127.0.0.1
fallback_dns: 8.8.8.8 8.8.4.4
dnssec: allow-downgrade
suid_sgid_blacklist: [/bin/fusermount, /bin/mount, /bin/ping, /bin/ping6, /bin/su, /bin/umount, /sbin/mount.nfs, /usr/bin/bsd-write, /usr/bin/chage, /usr/bin/chfn, /usr/bin/chsh, /usr/bin/mlocate, /usr/bin/mtr, /usr/bin/newgrp, /usr/bin/pkexec, /usr/bin/traceroute6.iputils, /usr/bin/wall, /usr/sbin/pppd]
random_ack_limit: "{{ 1000000 | random(start=1000) }}"
```

Dependencies
------------

None.

Example Playbook
----------------

    - hosts: servers
      roles:
         - { role: username.rolename, x: 42 }

License
-------

MIT

Author Information
------------------

[https://github.com/konstruktoid](https://github.com/konstruktoid "github.com/konstruktoid")

