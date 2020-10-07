# Structure

![Alt text](./images/ansible-role-hardening.svg)

```sh
.
├── LICENSE
├── README.md
├── STRUCTURE.md
├── TESTING.md
├── Vagrantfile
├── action-lint
│   ├── Dockerfile
│   ├── README.md
│   └── entrypoint.sh
├── defaults
│   └── main
│       ├── auditd.yml
│       ├── dns.yml
│       ├── limits.yml
│       ├── misc.yml
│       ├── module_blocklists.yml
│       ├── ntp.yml
│       ├── packages.yml
│       ├── sshd.yml
│       ├── suid_sgid_blocklist.yml
│       └── sysctl.yml
├── genREADME.sh
├── handlers
│   └── main.yml
├── images
│   └── ansible-role-hardening.svg
├── meta
│   └── main.yml
├── molecule
│   └── default
│       ├── INSTALL.rst
│       ├── converge.yml
│       ├── molecule.yml
│       └── verify.yml
├── postChecks.sh
├── provision
│   └── setup.sh
├── renovate.json
├── runTests.sh
├── tasks
│   ├── adduser.yml
│   ├── aide.yml
│   ├── apparmor.yml
│   ├── apport.yml
│   ├── auditd.yml
│   ├── cron.yml
│   ├── ctrlaltdel.yml
│   ├── disablefs.yml
│   ├── disablemod.yml
│   ├── disablenet.yml
│   ├── extras.yml
│   ├── firewall.yml
│   ├── fstab.yml
│   ├── hosts.yml
│   ├── issue.yml
│   ├── journalconf.yml
│   ├── limits.yml
│   ├── lockroot.yml
│   ├── logindconf.yml
│   ├── logindefs.yml
│   ├── main.yml
│   ├── motdnews.yml
│   ├── mount.yml
│   ├── packages.yml
│   ├── password.yml
│   ├── path.yml
│   ├── pkgupdate.yml
│   ├── post.yml
│   ├── postfix.yml
│   ├── pre.yml
│   ├── prelink.yml
│   ├── resolvedconf.yml
│   ├── rkhunter.yml
│   ├── rootaccess.yml
│   ├── sshdconfig.yml
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
    ├── debug_facts.yml
    ├── inventory
    └── test.yml

28 directories, 110 files
```
