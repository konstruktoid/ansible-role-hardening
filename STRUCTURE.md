# Structure


```sh
.
├── CODEOWNERS
├── LICENSE
├── README.md
├── SECURITY.md
├── STRUCTURE.md
├── TESTING.md
├── Vagrantfile
├── aar-doc_template.j2
├── action-lint
│   ├── Dockerfile
│   └── entrypoint.sh
├── defaults
│   └── main.yml
├── files
│   └── usr
│       └── share
│           └── dict
│               └── passwords.list
├── generate_defaults.py
├── generate_doc_defaults.sh
├── generate_molecule_env.sh
├── handlers
│   └── main.yml
├── meta
│   ├── argument_specs.yml
│   ├── main.yml
│   └── requirements.yml
├── molecule
│   ├── almalinux
│   │   └── molecule.yml
│   ├── custom
│   │   └── molecule.yml
│   ├── debian
│   │   └── molecule.yml
│   ├── default
│   │   ├── converge.yml
│   │   ├── molecule.yml
│   │   └── verify.yml
│   ├── docker
│   │   └── molecule.yml
│   ├── single
│   │   └── molecule.yml
│   └── ubuntu
│       └── molecule.yml
├── postChecks.sh
├── renovate.json
├── requirements-dev.txt
├── requirements-upstream.txt
├── requirements.yml
├── runTests.sh
├── tasks
│   ├── adduser.yml
│   ├── aide.yml
│   ├── apparmor.yml
│   ├── apport.yml
│   ├── auditd.yml
│   ├── automatic_updates.yml
│   ├── compilers.yml
│   ├── compilers_dnf_post_transaction_actions_plugin.yml
│   ├── cron.yml
│   ├── ctrlaltdel.yml
│   ├── disablewireless.yml
│   ├── extras.yml
│   ├── facts.yml
│   ├── fstab.yml
│   ├── hosts.yml
│   ├── ipv6.yml
│   ├── issue.yml
│   ├── journalconf.yml
│   ├── kernel.yml
│   ├── kernelmodules.yml
│   ├── limits.yml
│   ├── lockroot.yml
│   ├── logindconf.yml
│   ├── logindefs.yml
│   ├── main.yml
│   ├── motdnews.yml
│   ├── mount.yml
│   ├── netplan.yml
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
│   ├── ufw.yml
│   ├── umask.yml
│   ├── usbguard.yml
│   └── users.yml
├── templates
│   ├── etc
│   │   ├── adduser.conf.j2
│   │   ├── ansible
│   │   │   └── facts.d
│   │   │       └── sshkeys.fact
│   │   ├── apt
│   │   │   └── apt.conf.d
│   │   │       ├── 52unattended-upgrades-local.j2
│   │   │       └── 53unattended-upgrades-custom-origins.j2
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
│   │   │   ├── faillock.conf.j2
│   │   │   ├── limits.conf.j2
│   │   │   └── pwquality.conf.j2
│   │   ├── ssh
│   │   │   ├── ssh_config.j2
│   │   │   └── sshd_config.j2
│   │   ├── sysctl
│   │   │   ├── sysctl.apparmor.conf.j2
│   │   │   ├── sysctl.ipv6.conf.j2
│   │   │   └── sysctl.main.conf.j2
│   │   └── systemd
│   │       ├── coredump.conf.j2
│   │       ├── journald.conf.j2
│   │       ├── logind.conf.j2
│   │       ├── resolved.conf.j2
│   │       ├── system.conf.j2
│   │       ├── timesyncd.conf.j2
│   │       ├── tmp.mount.j2
│   │       └── user.conf.j2
│   ├── lib
│   │   └── systemd
│   │       └── system
│   │           ├── aidecheck.service.j2
│   │           └── aidecheck.timer.j2
│   └── usr
│       └── lib
│           └── tmpfiles.d
│               └── ssh.conf.j2
├── tests
│   ├── debug_facts.yml
│   ├── inventory
│   └── test.yml
└── tox.ini

40 directories, 124 files
```
