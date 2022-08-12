# Task Execution and Structure

## Tasks
![Task execution order](./images/ansible-role-hardening.svg)

## Structure

```sh
.
├── LICENSE
├── README.md
├── STRUCTURE.md
├── TESTING.md
├── Vagrantfile
├── defaults
│   └── main
│       ├── auditd.yml
│       ├── compilers.yml
│       ├── disablewireless.yml
│       ├── dns.yml
│       ├── ufw.yml
│       ├── ipv6.yml
│       ├── limits.yml
│       ├── misc.yml
│       ├── module_blocklists.yml
│       ├── mount.yml
│       ├── ntp.yml
│       ├── packages.yml
│       ├── password.yml
│       ├── sshd.yml
│       ├── suid_sgid_blocklist.yml
│       ├── sysctl.yml
│       └── users.yml
├── files
│   └── usr
│       └── share
│           └── dict
│               └── passwords.list
├── genREADME.sh
├── handlers
│   └── main.yml
├── images
│   └── ansible-role-hardening.svg
├── meta
│   └── main.yml
├── molecule
│   ├── almalinux
│   │   └── molecule.yml
│   ├── debian
│   │   └── molecule.yml
│   ├── default
│   │   ├── INSTALL.rst
│   │   ├── converge.yml
│   │   ├── molecule.yml
│   │   └── verify.yml
│   ├── redhat
│   │   └── molecule.yml
│   ├── single
│   │   └── molecule.yml
│   └── ubuntu
│       └── molecule.yml
├── postChecks.sh
├── provision
│   └── setup.sh
├── renovate.json
├── requirements-dev.txt
├── requirements.yml
├── runTests.sh
├── tasks
│   ├── adduser.yml
│   ├── aide.yml
│   ├── apparmor.yml
│   ├── apport.yml
│   ├── auditd.yml
│   ├── compilers.yml
│   ├── cron.yml
│   ├── ctrlaltdel.yml
│   ├── disablefs.yml
│   ├── disablemod.yml
│   ├── disablenet.yml
│   ├── disablewireless.yml
│   ├── extras.yml
│   ├── facts.yml
│   ├── ufw.yml
│   ├── fstab.yml
│   ├── hosts.yml
│   ├── ipv6.yml
│   ├── issue.yml
│   ├── journalconf.yml
│   ├── limits.yml
│   ├── lockroot.yml
│   ├── logindconf.yml
│   ├── logindefs.yml
│   ├── main.yml
│   ├── motdnews.yml
│   ├── mount.yml
│   ├── packagemgmt.yml
│   ├── packages.yml
│   ├── password.yml
│   ├── path.yml
│   ├── post.yml
│   ├── postfix.yml
│   ├── pre.yml
│   ├── prelink.yml
│   ├── resolvedconf.yml
│   ├── rkhunter.yml
│   ├── rootaccess.yml
│   ├── sshconfig.yml
│   ├── sudo.yml
│   ├── suid.yml
│   ├── sysctl.yml
│   ├── systemdconf.yml
│   ├── timesyncd.yml
│   ├── umask.yml
│   └── users.yml
├── templates
│   ├── etc
│   │   ├── adduser.conf.j2
│   │   ├── ansible
│   │   │   └── facts.d
│   │   │       ├── cpuinfo.fact
│   │   │       ├── reboot.fact
│   │   │       ├── sshkeys.fact
│   │   │       └── systemd.fact
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
│   │   ├── motd.j2
│   │   ├── pam.d
│   │   │   ├── common-account.j2
│   │   │   ├── common-auth.j2
│   │   │   ├── common-password.j2
│   │   │   └── login.j2
│   │   ├── profile.d
│   │   │   └── initpath.sh.j2
│   │   ├── security
│   │   │   └── limits.conf.j2
│   │   ├── ssh
│   │   │   ├── ssh_config.j2
│   │   │   └── sshd_config.j2
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
├── tests
│   ├── debug_facts.yml
│   ├── inventory
│   └── test.yml
└── tox.ini

34 directories, 124 files
```
