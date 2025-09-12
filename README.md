# Ansible Role for Server Hardening

This is an [Ansible](https://www.ansible.com/) role designed to enhance the
security of servers running on AlmaLinux, Debian, or Ubuntu.

It's [systemd](https://freedesktop.org/wiki/Software/systemd/) focused
and requires Ansible version 2.18 or higher.

The role supports the following operating systems:

- [AlmaLinux 9](https://wiki.almalinux.org/release-notes/#almalinux-9)
- [AlmaLinux 10](https://wiki.almalinux.org/release-notes/#almalinux-10)
- [Debian 12 (Bookworm)](https://www.debian.org/releases/bookworm/)
- [Ubuntu 22.04 (Jammy Jellyfish)](https://releases.ubuntu.com/jammy/)
- [Ubuntu 24.04 (Noble Numbat)](https://releases.ubuntu.com/noble/)

For those using AWS or Azure, there are also hardened Ubuntu Amazon
Machine Images (AMIs) and Azure virtual machine images available.

These are available in the [konstruktoid/hardened-images](https://github.com/konstruktoid/hardened-images)
repository. These images are built using [Packer](https://www.packer.io/) and
this Ansible role is used for configuration.

> **Note**
> Do not use this role without first testing in a non-operational environment.

> **Note**
> There is a [SLSA](https://slsa.dev/) artifact present under the
> [slsa action workflow](https://github.com/konstruktoid/ansible-role-hardening/actions/workflows/slsa.yml)
> for verification.

> **Note**
> All options and defaults are documented in [defaults/main.yml](defaults/main.yml)
> and [meta/argument_specs.yml](meta/argument_specs.yml).
> `ansible-doc -t role` can be used to view the documentation for this role as
> well.


## Examples

### Requirements

```yaml
---
roles:
  - name: konstruktoid.hardening
    version: v3.3.0
    src: https://github.com/konstruktoid/ansible-role-hardening.git
    scm: git
```

### Playbook

```yaml
---
- name: Import and use the hardening role
  hosts: localhost
  any_errors_fatal: true
  tasks:
    - name: Import the hardening role
      ansible.builtin.import_role:
        name: konstruktoid.hardening
      vars:
        kernel_lockdown: true
        manage_suid_sgid_permissions: false
        sshd_admin_net:
          - 10.0.2.0/24
          - 192.168.0.0/24
          - 192.168.1.0/24
        sshd_allow_groups:
          - sudo
        sshd_update_moduli: true
        sshd_match_users:
          - user: testuser01
            rules:
              - AllowUsers testuser01
              - AuthenticationMethods password
              - PasswordAuthentication yes
          - user: testuser02
            rules:
              - AllowUsers testuser02
              - Banner none
        ufw_rate_limit: true
```

### Local playbook using git checkout

```yaml
---
- name: Checkout and configure konstruktoid.hardening
  hosts: localhost
  any_errors_fatal: true
  tasks:
    - name: Clone hardening repository
      become: true
      tags:
        - always
      block:
        - name: Install git
          ansible.builtin.package:
            name: git
            state: present

        - name: Checkout konstruktoid.hardening
          become: true
          ansible.builtin.git:
            repo: https://github.com/konstruktoid/ansible-role-hardening
            dest: /etc/ansible/roles/konstruktoid.hardening
            version: v3.3.0

        - name: Remove git
          ansible.builtin.package:
            name: git
            state: absent

    - name: Include the hardening role
      ansible.builtin.include_role:
        name: konstruktoid.hardening
      vars:
        sshd_allow_groups:
          - ubuntu
        sshd_login_grace_time: 60
        sshd_max_auth_tries: 10
        sshd_use_dns: false
        sshd_update_moduli: true
```

## Note regarding UFW firewall rules

Instead of resetting `ufw` every run and by doing so causing network traffic
disruption, the role deletes every `ufw` rule that doesn't have a comment
ending with `ansible managed`.

The role also sets default deny policies, which means that firewall rules
needs to be created for any additional ports except those specified in
the `sshd_ports` and `ufw_outgoing_traffic` variables.

See [ufw(8)](https://manpages.ubuntu.com/manpages/noble/en/man8/ufw.8.html)
for more information.

## Task Execution and Structure

See [STRUCTURE.md](STRUCTURE.md) for tree of the role structure.

## Role testing

See [TESTING.md](TESTING.md).

## Role Arguments

|Option|Description|Default|
|---|---|---|
| adduser_conf_template | adduser.conf template location. | etc/adduser.conf.j2 |
| common_account_template | PAM common-account template location. | etc/pam.d/common-account.j2 |
| common_auth_template | PAM common-auth template location. | etc/pam.d/common-auth.j2 |
| common_password_template | PAM common-password template location. | etc/pam.d/common-password.j2 |
| coredump_conf_template | systemd coredump.conf template location. | etc/systemd/coredump.conf.j2 |
| faillock_conf_template | faillock.conf template location. | etc/security/faillock.conf.j2 |
| hardening_rules_template | auditd rules template location. | etc/audit/rules.d/hardening.rules.j2 |
| hosts_allow_template | /etc/hosts.allow template location. | etc/hosts.allow.j2 |
| hosts_deny_template | /etc/hosts.deny template location. | etc/hosts.deny.j2 |
| initpath_sh_template | profile initpath.sh template location. | etc/profile.d/initpath.sh.j2 |
| issue_template | /etc/issue template location. | etc/issue.j2 |
| journald_conf_template | systemd journald.conf template location. | etc/systemd/journald.conf.j2 |
| limits_conf_template | limits.conf template location. | etc/security/limits.conf.j2 |
| login_defs_template | /etc/login.defs template location. | etc/login.defs.j2 |
| login_template | login template location | etc/pam.d/login.j2 |
| logind_conf_template | systemd logind.conf template location. | etc/systemd/logind.conf.j2 |
| logrotate_conf_template | logrotate.conf template location. | etc/logrotate.conf.j2 |
| motd_template | /etc/motd template location. | etc/motd.j2 |
| pwquality_conf_template | pwquality.conf template location. | etc/security/pwquality.conf.j2 |
| resolved_conf_template | systemd resolved.conf template location. | etc/systemd/resolved.conf.j2 |
| rkhunter_template | rkhunter configuration template location. | etc/default/rkhunter.j2 |
| ssh_config_template | OpenSSH ssh_config template location. | etc/ssh/ssh_config.j2 |
| sshd_config_template | OpenSSH sshd_config template location. | etc/ssh/sshd_config.j2 |
| sshd_tmpfiles_template | OpenSSH tmpfiles template location. | usr/lib/tmpfiles.d/ssh.conf.j2 |
| sysctl_apparmor_config_template | AppArmor sysctl configuration template location. | etc/sysctl/sysctl.apparmor.conf.j2 |
| sysctl_ipv6_config_template | IPv6 sysctl configuration template location. | etc/sysctl/sysctl.ipv6.conf.j2 |
| sysctl_main_config_template | main sysctl configuration template location. | etc/sysctl/sysctl.main.conf.j2 |
| system_conf_template | systemd system.conf template location. | etc/systemd/system.conf.j2 |
| timesyncd_conf_template | systemd timesyncd.conf template location. | etc/systemd/timesyncd.conf.j2 |
| tmp_mount_template | tmp.mount template location. | etc/systemd/tmp.mount.j2 |
| unattended_upgrades_template | APT unattended-upgrades template location. | etc/apt/apt.conf.d/52unattended-upgrades-local.j2 |
| unattended_upgrades_custom_origins_template | APT unattended-upgrades for custom origins template location. | etc/apt/apt.conf.d/53unattended-upgrades-custom-origins.j2 |
| user_conf_template | systemd user.conf template location. | etc/systemd/user.conf.j2 |
| useradd_template | useradd template location. | etc/default/useradd.j2 |
| manage_pam | If True, manage PAM configuration files. | True |
| manage_faillock | If True, enable and manage faillock. | True |
| manage_pwquality | If True, enable and manage pwquality. | True |
| faillock | Faillock configuration options. | [{'admin_group': ''}, {'audit': True}, {'deny': 5}, {'dir': '/var/run/faillock'}, {'even_deny_root': True}, {'fail_interval': 900}, {'local_users_only': True}, {'no_log_info': False}, {'nodelay': True}, {'root_unlock_time': 600}, {'silent': False}, {'unlock_time': 600}] |
| login_defs | login.defs configuration options. | [{'login_retries': 5}, {'login_timeout': 60}, {'pass_max_days': 60}, {'pass_min_days': 1}, {'pass_warn_age': 7}] |
| password_remember | The number of previous passwords to remember and not allow the user to reuse. | 24 |
| pwquality | pwquality configuration options. | [{'dcredit': -1}, {'dictcheck': True}, {'dictpath': ''}, {'difok': 8}, {'enforce_for_root': True}, {'enforcing': True}, {'gecoscheck': True}, {'lcredit': -1}, {'local_users_only': True}, {'maxclassrepeat': 4}, {'maxrepeat': 3}, {'maxsequence': 3}, {'minclass': 4}, {'minlen': 15}, {'ocredit': -1}, {'retry': 3}, {'ucredit': -1}, {'usercheck': True}, {'usersubstr': 3}] |
| disable_root_account | If True, disable the root account. | True |
| manage_aide | If True, manage AIDE installation and configuration. | True |
| aide_checksums | Modifies the AIDE `Checksums` variable. | sha512 |
| aide_dir_exclusions | AIDE directories to exclude from checks. | ['/var/lib/docker', '/var/lib/lxcfs', '/var/lib/private/systemd', '/var/log/audit', '/var/log/journal'] |
| manage_timesyncd | If True, manage systemd-timesyncd installation and configuration. | True |
| fallback_ntp | A list of NTP server host names or IP addresses to be used as the fallback NTP servers. | ['ntp.netnod.se', 'ntp.ubuntu.com'] |
| ntp | A list of NTP server host names or IP addresses to be used as the primary NTP servers. | ['2.pool.ntp.org', 'time.nist.gov'] |
| manage_cron | If True, then `at` and `cron` will be restricted to the root user. | True |
| manage_sudo | If True, then manage sudo configuration. | True |
| manage_rkhunter | If True, manage rkhunter installation and configuration. | True |
| rkhunter_allow_ssh_prot_v1 | If the SSH protocol version 1 is allowed. | False |
| rkhunter_allow_ssh_root_user | If the root user is allowed to login via SSH. | False |
| rkhunter_mirrors_mode | Which mirrors are to be used for rkhunter updates. | 0 |
| rkhunter_update_mirrors | If True,  the mirrors file is to be checked for updates as well. | True |
| rkhunter_web_cmd | The command to use for downloading files from the Internet. | curl -fsSL |
| manage_path | If True, then the `PATH` variable will be set in `/etc/environment` and `/etc/profile.d/initpath.sh` will be created. | True |
| set_crypto_policy | Set and use cryptographic policies if `/etc/crypto-policies/config` exists and `set_crypto_policy: true`. | True |
| crypto_policy | The cryptographic policy to set if `set_crypto_policy: true`. | DEFAULT:NO-SHA1 |
| manage_ssh | If True, manage OpenSSH client and server configuration. | True |
| sshd_accept_env | Specifies what environment variables sent by the client will be copied into the session. | LANG LC_* |
| sshd_admin_net | Only the network(s) defined in `sshd_admin_net` are allowed to connect to `sshd_ports`. | ['192.168.0.0/24', '192.168.1.0/24'] |
| sshd_allow_agent_forwarding | Specifies whether ssh-agent forwarding is permitted. | False |
| sshd_allow_groups | If specified, login is allowed only for users whose primary group or supplementary group list matches one of the patterns. | ['sudo'] |
| sshd_allow_tcp_forwarding | Specifies whether TCP forwarding is permitted. | False |
| sshd_allow_users | If specified, login is allowed only for users whose user name matches one of the patterns. |  |
| sshd_authentication_methods | The authentication methods that must be successfully completed in order to grant access to a user. | any |
| sshd_authorized_principals_file | Specifies a file that lists principal names that are accepted for certificate authentication. | /etc/ssh/auth_principals/%u |
| sshd_banner | The contents of the specified file are sent to the remote user before authentication. | /etc/issue.net |
| sshd_ca_signature_algorithms | Specifies which algorithms are allowed for signing of certificates by certificate authorities. | ['ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521', 'ssh-ed25519', 'rsa-sha2-512'] |
| sshd_kbd_interactive_authentication | Specifies whether to allow keyboard-interactive authentication. | False |
| sshd_ciphers | Specifies the ciphers allowed. Multiple ciphers must be comma-separated. | ['chacha20-poly1305@openssh.com', 'aes256-gcm@openssh.com', 'aes256-ctr'] |
| sshd_client_alive_count_max | Sets the number of client alive messages which may be sent without sshd receiving any messages back from the client. | 1 |
| sshd_client_alive_interval | Sets a timeout interval in seconds after which if no data has been received from the client, sshd will send a message channel to request a response from the client. | 200 |
| sshd_compression | Specifies whether compression is enabled. | False |
| sshd_config_d_force_clear | Clear pre-existing custom configurations in /etc/ssh/sshd_config.d | False |
| sshd_config_force_replace | Force replace configuration file `/etc/ssh/sshd_config`. | False |
| sshd_debian_banner | Specifies whether the distribution-specified extra version suffix is included during initial protocol handshake. | False |
| sshd_deny_groups | Login is disallowed for users whose primary group or supplementary group list matches one of the patterns. | [] |
| sshd_deny_users | Login is disallowed for users whose user name matches one of the patterns. | [] |
| sshd_gateway_ports | Specifies whether remote hosts are allowed to connect to ports forwarded for the client. | False |
| sshd_gssapi_authentication | Specifies whether user authentication based on GSSAPI is allowed. | False |
| sshd_host_key_algorithms | Specifies the host key algorithms that the server offers. | ['ssh-ed25519-cert-v01@openssh.com', 'ssh-rsa-cert-v01@openssh.com', 'ssh-ed25519', 'ecdsa-sha2-nistp521-cert-v01@openssh.com', 'ecdsa-sha2-nistp384-cert-v01@openssh.com', 'ecdsa-sha2-nistp521', 'ecdsa-sha2-nistp384'] |
| sshd_host_keys_files | Specifies a file containing a private host key used by SSH. If empty `RSA`, `ECDSA`, and `ED25519` will be used, if supported by the installed sshd version. | [] |
| sshd_host_keys_group | Owner group of the host keys. | root |
| sshd_host_keys_mode | Host keys file mode. | 0600 |
| sshd_host_keys_owner | Owner of the host keys. | root |
| sshd_hostbased_authentication | Specifies whether rhosts or /etc/hosts.equiv authentication together with successful public key client host authentication is allowed. | False |
| sshd_ignore_rhosts | Specifies that .rhosts and .shosts files will not be used in HostbasedAuthentication. | True |
| sshd_ignore_user_known_hosts | Specifies whether sshd should ignore the user's ~/.ssh/known_hosts during HostbasedAuthentication and use only the system-wide known hosts file /etc/ssh/known_hosts. | True |
| sshd_kerberos_authentication | Specifies whether the password provided by the user for PasswordAuthentication will be validated through the Kerberos KDC. | False |
| sshd_kex_algorithms | Specifies the available KEX (Key Exchange) algorithms. | ['curve25519-sha256@libssh.org', 'diffie-hellman-group16-sha512', 'diffie-hellman-group18-sha512', 'ecdh-sha2-nistp521', 'ecdh-sha2-nistp384'] |
| sshd_listen | Specifies the addresses sshd should listen on. | ['0.0.0.0'] |
| sshd_log_level | Gives the verbosity level that is used when logging messages from sshd. | verbose |
| sshd_login_grace_time | The server disconnects after this time if the user has not successfully logged in. | 20 |
| sshd_macs | Specifies the available MAC (Message Authentication Code) algorithms. | ['hmac-sha2-512-etm@openssh.com', 'hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512', 'hmac-sha2-256'] |
| sshd_match_addresses | Add a conditional block for addresses. If all of the criteria on the Match line are satisfied, the rules/parameters defined override those set in the global section of the config file, until either another Match line or the end of the file. |  |
| sshd_match_groups | Add a conditional block for groups. If all of the criteria on the Match line are satisfied, the rules/parameters defined override those set in the global section of the config file, until either another Match line or the end of the file. |  |
| sshd_match_local_ports | Add a conditional block for ports. If all of the criteria on the Match line are satisfied, the rules/parameters defined override those set in the global section of the config file, until either another Match line or the end of the file. |  |
| sshd_match_users | Add a conditional block for users. If all of the criteria on the Match line are satisfied, the rules/parameters defined override those set in the global section of the config file, until either another Match line or the end of the file. |  |
| sshd_max_auth_tries | Specifies the maximum number of authentication attempts permitted per connection. | 3 |
| sshd_max_sessions | Specifies the maximum number of open sessions permitted per network connection. | 3 |
| sshd_max_startups | Specifies the maximum number of concurrent unauthenticated connections to the SSH daemon. | 10:30:60 |
| sshd_password_authentication | Specifies whether password authentication is allowed. | False |
| sshd_permit_empty_passwords | Specifies whether the server allows login to accounts with empty password strings. | False |
| sshd_permit_root_login | Specifies whether root can log in using ssh, if True then the option is set to prohibit-password. | False |
| sshd_permit_tunnel | Specifies whether tun device forwarding is allowed. | False |
| sshd_permit_user_environment | Specifies whether user environment variables are processed by sshd. | False |
| sshd_ports | Specifies the port number that sshd listens on. | [22] |
| sshd_print_last_log | Specifies whether sshd should print the last user login when a user logs in interactively. | True |
| sshd_print_motd | Specifies whether sshd should print /etc/motd when a user logs in interactively. | False |
| sshd_print_pam_motd | Specifies whether pam_motd should be enabled for sshd. | False |
| sshd_rekey_limit | Specifies the maximum amount of data that may be transmitted before the session key is renegotiated, optionally followed a maximum amount of time that may pass before the session key is renegotiated. | 512M 1h |
| sshd_required_ecdsa_size | Required ECDSA key size when generating new host keys. | 521 |
| sshd_required_rsa_size | Required RSA key size when generating new host keys. | 4096 |
| sshd_sftp_enabled | Specifies whether the SFTP subsystem should be enabled. | True |
| sshd_sftp_chroot | Specifies whether the SFTP subsystem should chroot users. | True |
| sshd_sftp_chroot_dir | Specifies the pathname of a directory to chroot to after authentication. | %h |
| sshd_sftp_only_group | Specifies the name of the group that will have access restricted to the sftp service only. |  |
| sshd_sftp_subsystem | Specifies the SFTP subsystem to use. | internal-sftp -f LOCAL6 -l INFO |
| sshd_strict_modes | Specifies whether sshd should check file modes and ownership of the user's files and home directory before accepting login. | True |
| sshd_syslog_facility | Gives the facility code that is used when logging messages from sshd. | auth |
| sshd_tcp_keep_alive | Specifies whether the system should send TCP keepalive messages to the other side. | False |
| sshd_trusted_user_ca_keys_base64 | Public keys of trusted certificate authoritites in base64 format. |  |
| sshd_trusted_user_ca_keys_file | Specifies a file containing public keys of certificate authorities that are trusted to sign user certificates for authentication. | /etc/ssh/trusted-user-ca-keys.pem |
| sshd_update_moduli | Specifies whether the moduli file should be updated. | False |
| sshd_update_moduli_url | Specifies the URL to download the moduli file from. | https://raw.githubusercontent.com/konstruktoid/ssh-moduli/main/moduli |
| sshd_use_dns | Specifies whether sshd should look up the remote host name, and to check that the resolved host name for the remote IP address maps back to the very same IP address. | False |
| sshd_use_pam | If true, this will enable PAM authentication using KbdInteractiveAuthentication and PasswordAuthentication in addition to PAM account and session module processing for all authentication types. | True |
| sshd_use_privilege_separation | Specifies whether sshd separates privileges by creating an unprivileged child process to deal with incoming network traffic. | sandbox |
| sshd_x11_forwarding | Specifies whether X11 forwarding is permitted. | False |
| disable_apport | If True, disable the `Apport` crash reporting system. | True |
| manage_issue | If True, then `/etc/issue`, `/etc/issue.net` and `/etc/motd` will be replaced with the available templates. | True |
| manage_kernel_modules | If True, then the listed modules will be blocked and blacklisted. | True |
| fs_modules_blocklist | Filesystem kernel modules to block and blacklist. | ['cramfs', 'freevxfs', 'hfs', 'hfsplus', 'jffs2', 'squashfs', 'udf'] |
| misc_modules_blocklist | Misc kernel modules to block and blacklist. | ['bluetooth', 'bnep', 'btusb', 'can', 'cpia2', 'firewire-core', 'floppy', 'ksmbd', 'n_hdlc', 'net-pf-31', 'pcspkr', 'soundcore', 'thunderbolt', 'usb-midi', 'usb-storage', 'uvcvideo', 'v4l2_common'] |
| net_modules_blocklist | Network kernel modules to block and blacklist. | ['atm', 'dccp', 'sctp', 'rds', 'tipc'] |
| manage_compilers | If True, then the listed compilers will restricted to the root user. | True |
| compilers | Compilers to restrict to the root user. | ['as', 'cargo', 'cc', 'cc-[0-9]*', 'clang-[0-9]*', 'gcc', 'gcc-[0-9]*', 'go', 'make', 'rustc'] |
| manage_login_defs | If True, then manage `/etc/login.defs` configuration. | True |
| disable_ipv6 | If True, disable IPv6 on the system. | False |
| sysctl_net_ipv6_conf_accept_ra_rtr_pref | If 0, the system denies IPv6 router solicitations. | 0 |
| ipv6_disable_sysctl_settings | IPv6 sysctl settings to disable IPv6. | [{'net.ipv6.conf.all.disable_ipv6': 1}, {'net.ipv6.conf.default.disable_ipv6': 1}] |
| ipv6_sysctl_settings | IPv6 sysctl settings. | [{'net.ipv6.conf.all.accept_ra': 0}, {'net.ipv6.conf.all.accept_redirects': 0}, {'net.ipv6.conf.all.accept_source_route': 0}, {'net.ipv6.conf.all.forwarding': 0}, {'net.ipv6.conf.all.use_tempaddr': 2}, {'net.ipv6.conf.default.accept_ra': 0}, {'net.ipv6.conf.default.accept_ra_defrtr': 0}, {'net.ipv6.conf.default.accept_ra_pinfo': 0}, {'net.ipv6.conf.default.accept_ra_rtr_pref': 0}, {'net.ipv6.conf.default.accept_redirects': 0}, {'net.ipv6.conf.default.accept_source_route': 0}, {'net.ipv6.conf.default.autoconf': 0}, {'net.ipv6.conf.default.dad_transmits': 0}, {'net.ipv6.conf.default.max_addresses': 1}, {'net.ipv6.conf.default.router_solicitations': 0}, {'net.ipv6.conf.default.use_tempaddr': 2}] |
| manage_apparmor | If True, manage `AppArmor` installation and configuration. | True |
| manage_hosts | If True, manage `/etc/hosts.allow` and `/etc/hosts.deny` configuration. | True |
| manage_ufw | If True, manage `UFW` installation and configuration. | True |
| ufw_outgoing_traffic | Allowed outgoing ports and protocols. | [{'port': 22, 'proto': 'tcp'}, 53, {'port': 80, 'proto': 'tcp'}, {'port': 123, 'proto': 'udp'}, {'port': 443, 'proto': 'tcp'}, 853, {'port': 4460, 'proto': 'tcp'}] |
| ufw_rate_limit | If True, rate limiting is enabled for incoming connections. | False |
| manage_journal | If True, manage `systemd-journald` installation and configuration. | True |
| rsyslog_filecreatemode | Set the file creation mode for rsyslog log files. | 0640 |
| journald_compress | If True, journal files will be compressed. | True |
| journald_forwardtosyslog | If True, forward journal messages to syslog. | False |
| journald_storage | Controls where to store journal data. | persistent |
| journald_permissions | Sets the permissions for journal files and directories. | 2640 |
| journald_group | The group that has access to the journal files. | systemd-journal |
| journald_user | The user that has access to the journal files. | root |
| journald_system_max_use | How much disk space the journal may use up at most. |  |
| manage_sysctl | If True, manage `sysctl` settings. | True |
| usr_lib_sysctl_d_dir | If True, use `/usr/lib/sysctl.d` as the sysctl configuration directory, otherwise use `/etc/sysctl.d`. | False |
| sysctl_conf_dir | Sets the sysctl configuration directory. | {{ '/usr/lib/sysctl.d' if usr_lib_sysctl_d_dir else '/etc/sysctl.d' }} |
| sysctl_dev_tty_ldisc_autoload | If 0, restrict loading TTY line disciplines to the CAP_SYS_MODULE capability. | 0 |
| apparmor_sysctl_settings | AppArmor sysctl settings. | [{'kernel.apparmor_display_secid_mode': 0}, {'kernel.apparmor_restrict_unprivileged_io_uring': 0}, {'kernel.apparmor_restrict_unprivileged_unconfined': 1}, {'kernel.apparmor_restrict_unprivileged_userns': 1}, {'kernel.apparmor_restrict_unprivileged_userns_complain': 0}, {'kernel.apparmor_restrict_unprivileged_userns_force': 0}, {'kernel.unprivileged_userns_apparmor_policy': 1}] |
| conntrack_sysctl_settings | Connection tracking sysctl settings. | [{'net.netfilter.nf_conntrack_max': 2000000}, {'net.netfilter.nf_conntrack_tcp_loose': 0}] |
| generic_sysctl_settings | Generic sysctl settings. | [{'fs.protected_fifos': 2}, {'fs.protected_regular': 2}, {'fs.protected_hardlinks': 1}, {'fs.protected_symlinks': 1}, {'fs.suid_dumpable': 0}, {'kernel.core_pattern': '|/bin/false'}, {'kernel.core_uses_pid': 1}, {'kernel.dmesg_restrict': 1}, {'kernel.kptr_restrict': 2}, {'kernel.panic': 60}, {'kernel.panic_on_oops': 1}, {'kernel.perf_event_paranoid': 2}, {'kernel.randomize_va_space': 2}, {'kernel.sysrq': 0}, {'kernel.unprivileged_bpf_disabled': 1}, {'kernel.yama.ptrace_scope': 2}, {'net.core.bpf_jit_harden': 2}, {'user.max_user_namespaces': 62967}] |
| ipv4_sysctl_settings | IPv4 sysctl settings. | [{'net.ipv4.conf.all.accept_redirects': 0}, {'net.ipv4.conf.all.accept_source_route': 0}, {'net.ipv4.conf.all.log_martians': 1}, {'net.ipv4.conf.all.rp_filter': 1}, {'net.ipv4.conf.all.secure_redirects': 1}, {'net.ipv4.conf.all.send_redirects': 0}, {'net.ipv4.conf.all.shared_media': 1}, {'net.ipv4.conf.default.accept_redirects': 0}, {'net.ipv4.conf.default.accept_source_route': 0}, {'net.ipv4.conf.default.log_martians': 1}, {'net.ipv4.conf.default.rp_filter': 1}, {'net.ipv4.conf.default.secure_redirects': 1}, {'net.ipv4.conf.default.send_redirects': 0}, {'net.ipv4.conf.default.shared_media': 1}, {'net.ipv4.icmp_echo_ignore_broadcasts': 1}, {'net.ipv4.icmp_ignore_bogus_error_responses': 1}, {'net.ipv4.ip_forward': 0}, {'net.ipv4.tcp_challenge_ack_limit': 2147483647}, {'net.ipv4.tcp_invalid_ratelimit': 500}, {'net.ipv4.tcp_max_syn_backlog': 20480}, {'net.ipv4.tcp_rfc1337': 1}, {'net.ipv4.tcp_syn_retries': 5}, {'net.ipv4.tcp_synack_retries': 5}, {'net.ipv4.tcp_syncookies': 1}, {'net.ipv4.tcp_timestamps': 1}] |
| manage_usbguard | If True, manage `USBGuard` installation and configuration. | True |
| usbguard_configuration_file | USBGuard configuration file path. | /etc/usbguard/usbguard-daemon.conf |
| usbguard_rulefile | USBGuard rule file path. | /etc/usbguard/rules.conf |
| usbguard_auditbackend | USBGuard audit events log backend. | LinuxAudit |
| usbguard_auditfilepath | USBGuard audit events log file path. | /var/log/usbguard/usbguard-audit.log |
| usbguard_authorizeddefault | Default authorized controller devices. | none |
| usbguard_devicemanagerbackend | Which device manager backend implementation to use. | uevent |
| usbguard_deviceruleswithport | Generate device specific rules including the 'via-port' attribute. | False |
| usbguard_hidepii | Hide personally identifiable information such as device serial numbers and hashes of descriptors from audit entries. | False |
| usbguard_implicitpolicytarget | How to treat USB devices that don’t match any rule in the policy. | block |
| usbguard_inserteddevicepolicy | How to treat USB devices that are already connected after the daemon starts. | apply-policy |
| usbguard_ipcaccesscontrolfiles | The files at this location will be interpreted by the daemon as IPC access control definition files. | /etc/usbguard/IPCAccessControl.d/ |
| usbguard_ipcallowedgroups | A list of groupnames that the daemon will accept IPC connections from. | ['plugdev', 'root', 'wheel'] |
| usbguard_ipcallowedusers | A list of usernames that the daemon will accept IPC connections from. | ['root'] |
| usbguard_presentcontrollerpolicy | How to treat USB controller devices that are already connected when the daemon starts. | keep |
| usbguard_presentdevicepolicy | How to treat USB devices that are already connected when the daemon starts. | apply-policy |
| usbguard_restorecontrollerdevicestate | Control whether the daemon will try to restore the attribute values to the state before modification on shutdown. | False |
| manage_suid_sgid_permissions | If True, remove suid and sgid permissions on the binaries listed in suid_sgid_blocklist. | True |
| suid_sgid_blocklist | List of binaries to remove suid and sgid permissions from. | ['7z', 'aa-exec', 'ab', 'agetty', 'alpine', 'ansible-playbook', 'ansible-test', 'aoss', 'apache2ctl', 'apt', 'apt-get', 'ar', 'aria2c', 'arj', 'arp', 'as', 'ascii-xfr', 'ascii85', 'ash', 'aspell', 'at', 'atobm', 'awk', 'aws', 'base32', 'base58', 'base64', 'basenc', 'basez', 'bash', 'batcat', 'bc', 'bconsole', 'bpftrace', 'bridge', 'bsd-write', 'bundle', 'bundler', 'busctl', 'busybox', 'byebug', 'bzip2', 'c89', 'c99', 'cabal', 'cancel', 'capsh', 'cat', 'cdist', 'certbot', 'chage', 'check_by_ssh', 'check_cups', 'check_log', 'check_memory', 'check_raid', 'check_ssl_cert', 'check_statusfile', 'chfn', 'chmod', 'choom', 'chown', 'chroot', 'chsh', 'clamscan', 'cmp', 'cobc', 'column', 'comm', 'composer', 'cowsay', 'cowthink', 'cp', 'cpan', 'cpio', 'cpulimit', 'crash', 'crontab', 'csh', 'csplit', 'csvtool', 'cupsfilter', 'curl', 'cut', 'dash', 'date', 'dc', 'dd', 'debugfs', 'dialog', 'diff', 'dig', 'distcc', 'dmesg', 'dmidecode', 'dmsetup', 'dnf', 'docker', 'dos2unix', 'dosbox', 'dotnet', 'dpkg', 'dstat', 'dvips', 'easy_install', 'eb', 'ed', 'efax', 'elvish', 'emacs', 'enscript', 'env', 'eqn', 'espeak', 'ex', 'exiftool', 'expand', 'expect', 'facter', 'file', 'find', 'finger', 'fish', 'flock', 'fmt', 'fold', 'fping', 'ftp', 'fusermount', 'gawk', 'gcc', 'gcloud', 'gcore', 'gdb', 'gem', 'genie', 'genisoimage', 'ghc', 'ghci', 'gimp', 'ginsh', 'git', 'grc', 'grep', 'gtester', 'gzip', 'hd', 'head', 'hexdump', 'highlight', 'hping3', 'iconv', 'iftop', 'install', 'ionice', 'ip', 'irb', 'ispell', 'jjs', 'joe', 'join', 'journalctl', 'jq', 'jrunscript', 'jtag', 'julia', 'knife', 'ksh', 'ksshell', 'ksu', 'kubectl', 'latex', 'latexmk', 'ld.so', 'ldconfig', 'less', 'lftp', 'links', 'ln', 'loginctl', 'logsave', 'look', 'lp', 'ltrace', 'lua', 'lualatex', 'luatex', 'lwp-download', 'lwp-request', 'mail', 'make', 'man', 'mawk', 'minicom', 'mksh', 'mksh-static', 'mlocate', 'more', 'mosquitto', 'mount', 'mount.nfs', 'msfconsole', 'msgattrib', 'msgcat', 'msgconv', 'msgfilter', 'msgmerge', 'msguniq', 'mtr', 'multitime', 'mv', 'mysql', 'nano', 'nasm', 'nawk', 'nc', 'ncdu', 'ncftp', 'neofetch', 'netfilter-persistent', 'newgrp', 'nft', 'nice', 'nl', 'nm', 'nmap', 'node', 'nohup', 'npm', 'nroff', 'nsenter', 'ntfs-3g', 'ntpdate', 'octave', 'od', 'openssl', 'openvpn', 'openvt', 'opkg', 'pandoc', 'paste', 'pax', 'pdb', 'pdflatex', 'pdftex', 'perf', 'perl', 'perlbug', 'pexec', 'pg', 'php', 'pic', 'pico', 'pidstat', 'ping', 'ping6', 'pip', 'pkexec', 'pkg', 'posh', 'pppd', 'pr', 'pry', 'psad', 'psftp', 'psql', 'ptx', 'puppet', 'pwsh', 'python', 'rake', 'rbash', 'rc', 'readelf', 'red', 'redcarpet', 'redis', 'restic', 'rev', 'rlogin', 'rlwrap', 'rpm', 'rpmdb', 'rpmquery', 'rpmverify', 'rsync', 'rtorrent', 'ruby', 'run-mailcap', 'run-parts', 'runscript', 'rview', 'rvim', 'sash', 'scanmem', 'scp', 'screen', 'script', 'scrot', 'sed', 'service', 'setarch', 'setfacl', 'setlock', 'sftp', 'sg', 'sh', 'shuf', 'slsh', 'smbclient', 'snap', 'socat', 'socket', 'soelim', 'softlimit', 'sort', 'split', 'sqlite3', 'sqlmap', 'ss', 'ssh', 'ssh-agent', 'ssh-keygen', 'ssh-keyscan', 'sshpass', 'start-stop-daemon', 'stdbuf', 'strace', 'strings', 'su', 'sysctl', 'systemctl', 'systemd-resolve', 'tac', 'tail', 'tar', 'task', 'taskset', 'tasksh', 'tbl', 'tclsh', 'tcpdump', 'tcsh', 'tdbtool', 'tee', 'telnet', 'terraform', 'tex', 'tftp', 'tic', 'time', 'timedatectl', 'timeout', 'tmate', 'tmux', 'top', 'torify', 'torsocks', 'traceroute6.iputils', 'troff', 'tshark', 'ul', 'umount', 'unexpand', 'uniq', 'unshare', 'unsquashfs', 'unzip', 'update-alternatives', 'uudecode', 'uuencode', 'vagrant', 'valgrind', 'varnishncsa', 'vi', 'view', 'vigr', 'vim', 'vimdiff', 'vipw', 'virsh', 'volatility', 'w3m', 'wall', 'watch', 'wc', 'wget', 'whiptail', 'whois', 'wireshark', 'wish', 'write', 'xargs', 'xdg-user-dir', 'xdotool', 'xelatex', 'xetex', 'xmodmap', 'xmore', 'xpad', 'xxd', 'xz', 'yarn', 'yash', 'yelp', 'yum', 'zathura', 'zip', 'zsh', 'zsoelim', 'zypper'] |
| disable_ctrlaltdel | Disable the Ctrl+Alt+Del key combination to reboot the system. | True |
| disable_prelink | Disable prelinking of binaries. | True |
| manage_users | If True, then the listed users will be removed and any home directories will have the permissions set to 0750. | True |
| delete_users | List of users to delete. | ['games', 'gnats', 'irc', 'list', 'news', 'sync', 'uucp'] |
| manage_limits | If True, manage system limits. | True |
| limit_nofile_hard | Maximum number of open files, hard resource limit | 1024 |
| limit_nofile_soft | Maximum number of open files, soft resource limit | 512 |
| limit_nproc_hard | Maximum number of processes, hard resource limit | 1024 |
| limit_nproc_soft | Maximum number of processes, soft resource limit | 512 |
| manage_adduser_conf | If True, the role will configure `adduser` and `useradd` using the available templates. | True |
| manage_postfix | If True, then the Postfix mail server will be configured if `/etc/postfix/main.cf` exists. | True |
| manage_package_managers | If True, then `apt` and `dnf` will be configured to use for example GPG verification and clean requirements on remove. | True |
| apt_hardening_options | Options used to configure the APT suite of tools. | [ 'Acquire::AllowDowngradeToInsecureRepositories "false";', 'Acquire::AllowInsecureRepositories "false";', 'Acquire::http::AllowRedirect "false";', 'APT::Get::AllowUnauthenticated "false";', 'APT::Get::AutomaticRemove "true";', 'APT::Install-Recommends "false";', 'APT::Install-Suggests "false";', 'APT::Periodic::AutocleanInterval "7";', 'APT::Sandbox::Seccomp "1";', 'Unattended-Upgrade::Remove-Unused-Dependencies "true";', 'Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";' ] |
| manage_fstab | If True, then any floppy devices will be removed from `/etc/fstab`. | True |
| manage_mounts | If True, `/proc` will be mounted with the `nosuid,nodev,noexec,hidepid` options, `/dev/shm` will be mounted with the `nosuid,nodev,noexec` options and `/tmp` will be mounted as tmpfs with the `nosuid,nodev,noexec` options using the available template. | True |
| hide_pid | This option controls who can access the information in `/proc/pid` directories | 2 |
| process_group | Specifies the ID of a group whose members are authorized to learn process information otherwise prohibited by hidepid. | 0 |
| automatic_updates | Configure automatic updates. | [{'enabled': True}, {'only_security': True}, {'reboot': False}, {'reboot_from_time': '2:00'}, {'reboot_time_margin_mins': 20}, {'custom_origins': ''}] |
| manage_netplan | If True, then any available netplan configuration files will have the permissions set to 0600. | True |
| manage_resolved | If True, then the systemd-resolved service will be installed and configured. | True |
| dns | A list of addresses to use as system DNS servers. | ['1.1.1.2', '9.9.9.9'] |
| fallback_dns | A list of addresses to use as the fallback DNS servers. | ['1.0.0.2', '149.112.112.112'] |
| dnssec | Set the DNSSEC mode for systemd-resolved. | allow-downgrade |
| dns_over_tls | Set the DNS over TLS mode for systemd-resolved. | opportunistic |
| manage_root_access | If True, then the root user will only be able to login using a console and the systemd debug-shell will be masked. | True |
| reboot_ubuntu | If True, an Ubuntu node will be rebooted if required. | False |
| manage_motdnews | If True, then `apt-news`, `motd-news` and Ubuntu Pro will be disabled. | True |
| system_upgrade | If True, then the system will be upgraded to the latest version using `apt` or `dnf`. | True |
| packages_blocklist | Packages that will be removed from the system if they are installed. | ['apport', 'autofs', 'avahi', 'beep', 'ftp', 'git', 'inetutils-telnet', 'pastebinit', 'popularity-contest', 'prelink', 'rpcbind', 'rsh', 'rsh-server', 'rsync', 'talk', 'telnet', 'telnet-server', 'tftp', 'tftpd', 'tnftp', 'tuned', 'vsftpd', 'whoopsie', 'xinetd', 'yp-tools', 'ypbind'] |
| packages_debian | Packages to install on Debian-based systems. | ['acct', 'apparmor-profiles', 'apparmor-utils', 'apt-listchanges', 'apt-show-versions', 'audispd-plugins', 'auditd', 'cracklib-runtime', 'curl', 'debsums', 'gnupg2', 'libpam-apparmor', 'libpam-cap', 'libpam-modules', 'libpam-tmpdir', 'lsb-release', 'needrestart', 'openssh-server', 'postfix', 'rsyslog', 'sysstat', 'systemd-journal-remote', 'tcpd', 'vlock', 'wamerican'] |
| packages_redhat | Packages to install on Red Hat-based systems. | ['audispd-plugins', 'audit', 'cracklib', 'curl', 'gnupg2', 'openssh-server', 'needrestart', 'postfix', 'psacct', 'python3-dnf-plugin-post-transaction-actions', 'rsyslog', 'rsyslog-gnutls', 'systemd-journal-remote', 'vlock', 'words'] |
| packages_ubuntu | Packages to install on Ubuntu-based systems. | ['fwupd', 'secureboot-db', 'snapd'] |
| manage_logind | If True, then the systemd-logind service will be configured using the available template. | True |
| logind | Configure systemd-logind settings. | [{'killuserprocesses': True}, {'killexcludeusers': "['root']"}, {'idleaction': 'lock'}, {'idleactionsec': '15min'}, {'removeipc': True}] |
| disable_wireless | If True, turn off all wireless interfaces. | False |
| manage_auditd | If True, then the Linux Audit System will configured and enabled at boot using GRUB. | True |
| auditd_apply_audit_rules | If True, the role applies the auditd rules from the included template file. | True |
| auditd_action_mail_acct | This option should contain a valid email address or alias. | root |
| auditd_admin_space_left_action | This parameter tells the system what action to take when the system has detected that it is starting to get low on disk space. | suspend |
| auditd_disk_error_action | This parameter tells the system what action to take whenever there is an error detected when writing audit events to disk or rotating logs. | suspend |
| auditd_disk_full_action | This parameter tells the system what action to take when the system has detected that the partition to which log files are written has become full. | suspend |
| auditd_enable_flag | Set enabled flag for auditd service. | 2 |
| auditd_flush | When to flush the audit records to disk. | incremental_async |
| auditd_max_log_file | This keyword specifies the maximum file size in megabytes. When this limit is reached, it will trigger a configurable action. | 20 |
| auditd_max_log_file_action | This parameter tells the system what action to take when the system has detected that the max file size limit has been reached. | rotate |
| auditd_mode | Set failure mode. | 1 |
| auditd_num_logs | Specifies the number of log files to keep if rotate is given as the max_log_file_action. | 5 |
| auditd_space_left | If the free space in the filesystem containing log_file drops below this value (in megabytes), the audit daemon takes the action specified by space_left_action. | 75 |
| auditd_space_left_action | This parameter tells the system what action to take when the system has detected that it is starting to get low on disk space. | email |
| grub_audit_backlog_cmdline | Set the audit backlog limit in the GRUB command line. | audit_backlog_limit=8192 |
| grub_audit_cmdline | Enable auditd in the GRUB command line. | audit=1 |
| manage_systemd | If True, then the role will configure /etc/systemd/system.conf and /etc/systemd/user.conf using the available templates. | True |
| session_timeout | Sets, in seconds, the TMOUT environment variable if systemd version is 252 or lower. If version 252 or higher, the session_timeout value will be set as StopIdleSessionSec. | 900 |
| umask_value | Sets the default umask value. | 077 |
| manage_kernel | If True, then additional kernel settings will be configured. | True |
| allow_virtual_system_calls | Allow virtual system calls (vsyscall). | True |
| enable_page_poisoning | Enable kernel page poisoning. | True |
| kernel_lockdown | Configures kernel_lockdown. | False |
| page_table_isolation | Enable page table isolation (PTI). | True |
| slub_debugger_poisoning | Enable SLUB debugger poisoning. | False |
| manage_password | Manage PAM and various password settings. | True |
| manage_packages | If True, then the role will install the packages listed in `packages_debian`, `packages_redhat` and `packages_ubuntu`. | True |

#### Options for main > faillock

|Option|Description|Default|
|---|---|---|
| admin_group | Members of the group will be handled the same as the root account |  |
| audit | Will log the user name into the system log if the user is not found |  |
| deny | Deny access if the number of login failures exceeds the value of this option. |  |
| dir | Where the user files with the failure records are kept. |  |
| even_deny_root | Root account can become locked as well as regular accounts. |  |
| fail_interval | The length of the interval during which the consecutive authentication failures must happen for the user account to lock out. |  |
| local_users_only | Only track failed user authentications attempts for local users in /etc/passwd. |  |
| no_log_info | Don't log informative messages via syslog(3). |  |
| nodelay | Don't enforce a delay after authentication failures. |  |
| root_unlock_time | Allow access after N seconds to root account after the account is locked. |  |
| silent | Don't print informative messages to the user. |  |
| unlock_time | Allow access after N seconds to user accounts after the account is locked. |  |

#### Options for main > login_defs

|Option|Description|Default|
|---|---|---|
| login_retries | Maximum number of login retries in case of bad password. |  |
| login_timeout | Max time in seconds for login. |  |
| pass_max_days | The maximum number of days a password may be used. If the password is older than this, a password change will be forced. |  |
| pass_min_days | The minimum number of days allowed between password changes. If a user tries to change their password before this time, the change will be denied. |  |
| pass_warn_age | The number of days before password expiration that the user will be warned about the impending expiration. |  |

#### Options for main > pwquality

|Option|Description|Default|
|---|---|---|
| dcredit | The maximum credit for having digits in the new password. |  |
| dictcheck | Check whether the password matches a word in a dictionary. |  |
| dictpath | The path to the dictionary file used for password strength checking. |  |
| difok | The number of characters that must be different between the new password and the old one. |  |
| enforce_for_root | The module will return error on failed check even if the user changing the password is root. |  |
| enforcing | Reject the password if it fails the checks, otherwise only print the warning. |  |
| gecoscheck | Check whether the password matches a word in the GECOS field of the user account. |  |
| lcredit | The maximum credit for having lowercase letters in the new password. |  |
| local_users_only | The module will not test the password quality for users that are not present in the `/etc/passwd` file. |  |
| maxclassrepeat | Reject passwords which contain more than N consecutive characters of the same class. |  |
| maxrepeat | Reject passwords which contain more than N consecutive characters. |  |
| maxsequence | Reject passwords which contain monotonic character sequences longer than N. |  |
| minclass | The minimum number of character classes that must be present in the new password. |  |
| minlen | The minimum length of the new password. |  |
| ocredit | This is the maximum credit for having other characters in the new password. |  |
| retry | The number of times the user is allowed to retry entering a password that passes the checks. |  |
| ucredit | The maximum credit for having uppercase letters in the new password. |  |
| usercheck | Check whether the password (with possible modifications) contains the user name in some form. |  |
| usersubstr | Check whether the password contains a substring of at least N length |  |

#### Options for main > ipv6_disable_sysctl_settings

|Option|Description|Default|
|---|---|---|
| net.ipv6.conf.all.disable_ipv6 | If 1, the system disables IPv6 on all interfaces. |  |
| net.ipv6.conf.default.disable_ipv6 | If 1, the system disables IPv6 on the default interface. |  |

#### Options for main > ipv6_sysctl_settings

|Option|Description|Default|
|---|---|---|
| net.ipv6.conf.all.accept_ra | If 0, the system does not accept IPv6 router advertisements. |  |
| net.ipv6.conf.all.accept_redirects | If 0, the system does not accept IPv6 redirects. |  |
| net.ipv6.conf.all.accept_source_route | If 0, deny forwarding of IPv6 Source Routed Packets |  |
| net.ipv6.conf.all.forwarding | If 0, denies IPv6 forwarding. |  |
| net.ipv6.conf.all.use_tempaddr | Preference for IPv6 Privacy Extensions on all interfaces. | 2 |
| net.ipv6.conf.default.accept_ra | If 0, the system does not accept IPv6 router advertisements on the default interface. |  |
| net.ipv6.conf.default.accept_ra_defrtr | If 0, the system does not accept default routers from IPv6 router advertisements on the default interface. |  |
| net.ipv6.conf.default.accept_ra_pinfo | If 0, the system does not accept prefix information from IPv6 router advertisements on the default interface. |  |
| net.ipv6.conf.default.accept_ra_rtr_pref | If 0, the system does not accept router preference from IPv6 router advertisments on the default interface. |  |
| net.ipv6.conf.default.accept_redirects | If 0, the system does not accept IPv6 redirects on the default interface. | 0 |
| net.ipv6.conf.default.accept_source_route | If 0, deny forwarding of IPv6 Source Routed Packets on the default interface. | 0 |
| net.ipv6.conf.default.autoconf | If 0, the system doesn't autoconfigure addresses using Prefix Information in Router Advertisements. | 0 |
| net.ipv6.conf.default.dad_transmits | The amount of Duplicate Address Detection probes to send. | 0 |
| net.ipv6.conf.default.max_addresses | Maximum number of autoconfigured IPv6 addresses per interface. | 1 |
| net.ipv6.conf.default.router_solicitations | Number of Router Solicitations to send until assuming no routers are present. | 0 |
| net.ipv6.conf.default.use_tempaddr | Preference for IPv6 Privacy Extensions on the default interface. | 2 |

#### Options for main > apparmor_sysctl_settings

|Option|Description|Default|
|---|---|---|
| kernel.apparmor_display_secid_mode | If 1, AppArmor will provide a human-readable mapping of internal security IDs. |  |
| kernel.apparmor_restrict_unprivileged_io_uring | If 1, restrict unprivileged io_uring operations. |  |
| kernel.apparmor_restrict_unprivileged_unconfined | If 1, enforces extra security restrictions on unprivileged unconfined processes. |  |
| kernel.apparmor_restrict_unprivileged_userns | If 1, restricts unprivileged user namespaces. |  |
| kernel.apparmor_restrict_unprivileged_userns_complain | If 1, unprivileged user namespaces will be put into complain mode. |  |
| kernel.apparmor_restrict_unprivileged_userns_force | If 1, all confined applications will have the user namespace mediation enforced. |  |
| kernel.unprivileged_userns_apparmor_policy | If 1, unprivileged user namespaces will be restricted to the AppArmor policy. |  |

#### Options for main > conntrack_sysctl_settings

|Option|Description|Default|
|---|---|---|
| net.netfilter.nf_conntrack_max | The maximum number of connections that the system’s connection tracking table can hold at any time. |  |
| net.netfilter.nf_conntrack_tcp_loose | If 0, the system will not allow TCP connections to be established without a SYN packet. |  |

#### Options for main > generic_sysctl_settings

|Option|Description|Default|
|---|---|---|
| fs.protected_fifos | Avoid unintentional writes to an attacker-controlled FIFO, where a program expected to create a regular file. |  |
| fs.protected_regular | Avoid unintentional writes to an attacker-controlled regular file, where a program expected to create one. |  |
| fs.protected_hardlinks | Restrict hard links to files that are not owned by the user. |  |
| fs.protected_symlinks | Restrict symbolic links to files that are not owned by the user. |  |
| fs.suid_dumpable | Set the core dump mode for setuid or otherwise protected/tainted binaries. |  |
| kernel.core_pattern | Specify a core dumpfile pattern name. |  |
| kernel.core_uses_pid | If 1, the core dump file name will include the PID of the process that created it. |  |
| kernel.dmesg_restrict | If 1, unprivileged users are prevented from using dmesg to view messages from the kernel’s log buffer. |  |
| kernel.kptr_restrict | Whether restrictions are placed on exposing kernel addresses via /proc and other interfaces. |  |
| kernel.panic | The value in this file determines the behaviour of the kernel on a panic. |  |
| kernel.panic_on_oops | If 1, Panic immediately. If the panic sysctl is also non-zero then the machine will be rebooted. |  |
| kernel.perf_event_paranoid | Controls use of the performance events system by unprivileged users. | 2 |
| kernel.randomize_va_space | Select the type of process address space randomization that is used in the system. |  |
| kernel.sysrq | If 1, the magic SysRq key is enabled. |  |
| kernel.unprivileged_bpf_disabled | Controls whether BPF programs are disabled for unprivileged users. |  |
| kernel.yama.ptrace_scope | Select the what processes can be debugged with ptrace. | 2 |
| net.core.bpf_jit_harden | Level of hardening applied to the BPF JIT compiler. |  |
| user.max_user_namespaces | The maximum number of user namespaces that can be created by a user. |  |

#### Options for main > ipv4_sysctl_settings

|Option|Description|Default|
|---|---|---|
| net.ipv4.conf.all.accept_redirects | If 0, the system does not accept IPv4 redirects. |  |
| net.ipv4.conf.all.accept_source_route | If 0, deny IPv4 source routing. |  |
| net.ipv4.conf.all.log_martians | If 1, log packets with un-routable source addresses to the kernel log. |  |
| net.ipv4.conf.all.rp_filter | Set the reverse path filtering mode for all interfaces. |  |
| net.ipv4.conf.all.secure_redirects | If 1, accept ICMP redirect messages only to gateways listed in the interface's current gateway list. Overridden by shared_media. |  |
| net.ipv4.conf.all.send_redirects | If 0, the system does not send ICMP redirect messages. |  |
| net.ipv4.conf.all.shared_media | If 1, indicates that the media is shared with different subnets, overrides secure_redirects. |  |
| net.ipv4.conf.default.accept_redirects | If 0, the system does not accept IPv4 redirects on the default interface. |  |
| net.ipv4.conf.default.accept_source_route | If 0, deny IPv4 source routing on the default interface. |  |
| net.ipv4.conf.default.log_martians | If 1, log packets with un-routable source addresses to the kernel log on the default interface. |  |
| net.ipv4.conf.default.rp_filter | Set the reverse path filtering mode for the default interface. |  |
| net.ipv4.conf.default.secure_redirects | If 1, accept ICMP redirect messages only to gateways listed in the interface's current gateway list on the default interface. Overridden by shared_media. |  |
| net.ipv4.conf.default.send_redirects | net.ipv4.conf.default.send_redirects description |  |
| net.ipv4.conf.default.shared_media | If 1, indicates that the media is shared with different subnets, overrides secure_redirects on the default interface. |  |
| net.ipv4.icmp_echo_ignore_broadcasts | If 1, the system ignores ICMP echo requests sent to broadcast addresses. |  |
| net.ipv4.icmp_ignore_bogus_error_responses | If 1, the system ignores bogus ICMP responses. |  |
| net.ipv4.ip_forward | If 1, the system forwards IPv4 packets between interfaces. |  |
| net.ipv4.tcp_challenge_ack_limit | Set the TCP challenge ACK limit. |  |
| net.ipv4.tcp_invalid_ratelimit | The maximal rate for sending duplicate acknowledgments in response to incoming TCP packets, in milliseconds. |  |
| net.ipv4.tcp_max_syn_backlog | The number of SYN requests the kernel can queue before it starts dropping them. |  |
| net.ipv4.tcp_rfc1337 | If 1, the system will not accept TCP connections that are vulnerable to the TCP sequence number attack described in RFC 1337. |  |
| net.ipv4.tcp_syn_retries | Number of times initial SYNs for an active TCP connection attempt will be retransmitted. Should not be higher than 127. |  |
| net.ipv4.tcp_synack_retries | Number of times SYNACKs for a passive TCP connection attempt will be retransmitted. Should not be higher than 255. |  |
| net.ipv4.tcp_syncookies | If 1, the system will use TCP SYN cookies to protect against SYN flood attacks. |  |
| net.ipv4.tcp_timestamps | Enable timestamps as defined in RFC1323. |  |

#### Options for main > automatic_updates

|Option|Description|Default|
|---|---|---|
| enabled | If True, install and configure `dnf-automatic` or `unattended-upgrades`, depending on the distribution. |  |
| only_security | If True, only security updates will be installed automatically. |  |
| reboot | If True, it will reboot the system if needed. |  |
| reboot_from_time | If system reboot is enabled, the variable sets the reboot time, with added random minutes from `reboot_time_margin_mins`. |  |
| reboot_time_margin_mins | Add minutes to the reboot time, set using `reboot_from_time`. |  |
| custom_origins | Add custom origins to unattended upgrades through a list of strings. For Debian it is "origin=<ORIGIN>,archive=<ARCHIVE>". For Ubuntu it is "<ORIGIN>:<ARCHIVE>". |  |

#### Options for main > logind

|Option|Description|Default|
|---|---|---|
| killuserprocesses | Configures whether the processes of a user should be killed when the user logs out. |  |
| killexcludeusers | A list of usernames that override the KillUserProcesses setting. |  |
| idleaction | Configures the action to take when the system is idle. |  |
| idleactionsec | Configures the delay after which the action configured in `IdleAction` is taken after the system is idle. |  |
| removeipc | Controls whether System V and POSIX IPC objects belonging to the user shall be removed when the user fully logs out. |  |

#### Choices for main > rkhunter_mirrors_mode

|Choice|
|---|
| 0 |
| 1 |
| 2 |

#### Choices for main > sshd_allow_tcp_forwarding

|Choice|
|---|
| all |
| False |
| local |
| remote |
| True |

#### Choices for main > sshd_log_level

|Choice|
|---|
| debug |
| debug1 |
| debug2 |
| debug3 |
| error |
| fatal |
| info |
| quiet |
| verbose |

#### Choices for main > sshd_syslog_facility

|Choice|
|---|
| auth |
| daemon |
| user |
| local0 |
| local1 |
| local2 |
| local3 |
| local4 |
| local5 |
| local6 |
| local7 |

#### Choices for main > sshd_use_privilege_separation

|Choice|
|---|
| yes |
| no |
| sandbox |

#### Choices for main > ipv6_sysctl_settings > net.ipv6.conf.all.use_tempaddr

|Choice|
|---|
| 0 |
| 1 |
| 2 |

#### Choices for main > ipv6_sysctl_settings > net.ipv6.conf.default.use_tempaddr

|Choice|
|---|
| 0 |
| 1 |
| 2 |

#### Choices for main > journald_storage

|Choice|
|---|
| auto |
| none |
| persistent |
| volatile |

#### Choices for main > generic_sysctl_settings > fs.protected_fifos

|Choice|
|---|
| 0 |
| 1 |
| 2 |

#### Choices for main > generic_sysctl_settings > fs.protected_regular

|Choice|
|---|
| 0 |
| 1 |
| 2 |

#### Choices for main > generic_sysctl_settings > fs.protected_hardlinks

|Choice|
|---|
| 0 |
| 1 |

#### Choices for main > generic_sysctl_settings > fs.protected_symlinks

|Choice|
|---|
| 0 |
| 1 |

#### Choices for main > generic_sysctl_settings > fs.suid_dumpable

|Choice|
|---|
| 0 |
| 1 |
| 2 |

#### Choices for main > generic_sysctl_settings > kernel.kptr_restrict

|Choice|
|---|
| 0 |
| 1 |
| 2 |

#### Choices for main > generic_sysctl_settings > kernel.panic

|Choice|
|---|
| -1 |
| 0 |
| 60 |

#### Choices for main > generic_sysctl_settings > kernel.perf_event_paranoid

|Choice|
|---|
| -1 |
| 0 |
| 1 |
| 2 |

#### Choices for main > generic_sysctl_settings > kernel.randomize_va_space

|Choice|
|---|
| 0 |
| 1 |
| 2 |

#### Choices for main > generic_sysctl_settings > kernel.unprivileged_bpf_disabled

|Choice|
|---|
| 0 |
| 1 |
| 2 |

#### Choices for main > generic_sysctl_settings > kernel.yama.ptrace_scope

|Choice|
|---|
| 0 |
| 1 |
| 2 |
| 3 |

#### Choices for main > generic_sysctl_settings > net.core.bpf_jit_harden

|Choice|
|---|
| 0 |
| 1 |
| 2 |

#### Choices for main > ipv4_sysctl_settings > net.ipv4.conf.all.rp_filter

|Choice|
|---|
| 0 |
| 1 |
| 2 |

#### Choices for main > ipv4_sysctl_settings > net.ipv4.conf.default.rp_filter

|Choice|
|---|
| 0 |
| 1 |
| 2 |

#### Choices for main > ipv4_sysctl_settings > net.ipv4.tcp_timestamps

|Choice|
|---|
| 0 |
| 1 |
| 2 |

#### Choices for main > usbguard_auditbackend

|Choice|
|---|
| FileAudit |
| LinuxAudit |

#### Choices for main > usbguard_authorizeddefault

|Choice|
|---|
| all |
| internal |
| keep |
| none |

#### Choices for main > usbguard_devicemanagerbackend

|Choice|
|---|
| uevent |
| umockdev |

#### Choices for main > usbguard_implicitpolicytarget

|Choice|
|---|
| allow |
| block |
| reject |

#### Choices for main > usbguard_inserteddevicepolicy

|Choice|
|---|
| apply-policy |
| block |
| reject |

#### Choices for main > usbguard_presentcontrollerpolicy

|Choice|
|---|
| allow |
| apply-policy |
| block |
| keep |
| reject |

#### Choices for main > usbguard_presentdevicepolicy

|Choice|
|---|
| allow |
| apply-policy |
| block |
| keep |
| reject |

#### Choices for main > hide_pid

|Choice|
|---|
| 0 |
| 1 |
| 2 |

#### Choices for main > dnssec

|Choice|
|---|
| allow-downgrade |
| False |
| True |

#### Choices for main > dns_over_tls

|Choice|
|---|
| opportunistic |
| False |
| True |

#### Choices for main > logind > idleaction

|Choice|
|---|
| halt |
| hibernate |
| hybrid-sleep |
| ignore |
| kexec |
| lock |
| poweroff |
| reboot |
| suspend |
| suspend-then-hibernate |
| sleep |

#### Choices for main > auditd_admin_space_left_action

|Choice|
|---|
| email |
| exec |
| halt |
| ignore |
| rotate |
| single |
| suspend |
| syslog |

#### Choices for main > auditd_disk_error_action

|Choice|
|---|
| email |
| exec |
| halt |
| ignore |
| rotate |
| single |
| suspend |
| syslog |

#### Choices for main > auditd_disk_full_action

|Choice|
|---|
| email |
| exec |
| halt |
| ignore |
| rotate |
| single |
| suspend |
| syslog |

#### Choices for main > auditd_enable_flag

|Choice|
|---|
| 0 |
| 1 |
| 2 |

#### Choices for main > auditd_flush

|Choice|
|---|
| data |
| incremental_async |
| incremental |
| none |
| sync |

#### Choices for main > auditd_max_log_file_action

|Choice|
|---|
| ignore |
| keep_logs |
| rotate |
| syslog |
| suspend |

#### Choices for main > auditd_mode

|Choice|
|---|
| 0 |
| 1 |
| 2 |

#### Choices for main > auditd_space_left_action

|Choice|
|---|
| email |
| exec |
| halt |
| ignore |
| rotate |
| single |
| suspend |
| syslog |

#### Choices for main > kernel_lockdown

|Choice|
|---|
| confidentiality |
| False |
| integrity |
| none |
| True |



## Dependencies
None.


## Recommended Reading

[Comparing the DISA STIG and CIS Benchmark values](https://github.com/konstruktoid/publications/blob/master/ubuntu_comparing_guides_benchmarks.md)

[Center for Internet Security Linux Benchmarks](https://www.cisecurity.org/cis-benchmarks/)

[Common Configuration Enumeration](https://nvd.nist.gov/cce/index.cfm)

[DISA Security Technical Implementation Guides](https://public.cyber.mil/stigs/downloads/?_dl_facet_stigs=operating-systems%2Cunix-linux)

[SCAP Security Guides](https://complianceascode.github.io/content-pages/guides/index.html)

[Security focused systemd configuration](https://github.com/konstruktoid/hardening/blob/master/systemd.adoc)

## Contributing

Do you want to contribute? Great! Contributions are always welcome,
no matter how large or small. If you found something odd, feel free to submit a
issue, improve the code by creating a pull request, or by
[sponsoring this project](https://github.com/sponsors/konstruktoid).

### Guidelines

The [argument_specs.yml](meta/argument_specs.yml) file is used to generate the
documentation and defaults for this role, so please ensure that any changes
made to the role are also reflected in the `argument_specs.yml` file.

After making changes, run `bash generate_doc_defaults.sh` to regenerate the defaults file,
README and other documentation files.

Last but not least, ensure that the role passes all tests by running
`tox run -e devel,docker`.

## License

Apache License Version 2.0

## Author Information

[https://github.com/konstruktoid](https://github.com/konstruktoid "github.com/konstruktoid")
