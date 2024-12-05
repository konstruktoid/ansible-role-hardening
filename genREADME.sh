#!/bin/sh

if [ -z "${ANSIBLE_V}" ]; then
  ANSIBLE_V="$(grep min_ansible_version meta/main.yml | awk '{print $NF}' | tr -d '\"')"
fi

{
echo "# Ansible Role for Server Hardening

This is an [Ansible](https://www.ansible.com/) role designed to enhance the
security of servers running on AlmaLinux, Debian, or Ubuntu.

It's [systemd](https://freedesktop.org/wiki/Software/systemd/) focused
and requires Ansible version 2.15 or higher.

The role supports the following operating systems:

- [AlmaLinux 9](https://wiki.almalinux.org/release-notes/#almalinux-9)
- [Debian 11 (Bullseye)](https://www.debian.org/releases/bullseye/)
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

## Dependencies

None.

## Examples

### Requirements

\`\`\`yaml
---
roles:
  - name: konstruktoid.hardening
    version: v2.3.0
    src: https://github.com/konstruktoid/ansible-role-hardening.git
    scm: git
\`\`\`

### Playbook

\`\`\`yaml
---
- name: Import and use the hardening role
  hosts: localhost
  any_errors_fatal: true
  tasks:
    - name: Import the hardening role
      ansible.builtin.import_role:
        name: konstruktoid.hardening
      vars:
        sshd_admin_net:
          - 10.0.2.0/24
          - 192.168.0.0/24
          - 192.168.1.0/24
        manage_suid_sgid_permissions: false
\`\`\`

### Local playbook using git checkout

\`\`\`yaml
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
            version: v2.3.0

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
\`\`\`

## Note regarding UFW firewall rules

Instead of resetting \`ufw\` every run and by doing so causing network traffic
disruption, the role deletes every \`ufw\` rule without
\`comment: ansible managed\` task parameter and value.

The role also sets default deny policies, which means that firewall rules
needs to be created for any additional ports except those specified in
the \`sshd_ports\` and \`ufw_outgoing_traffic\` variables.

See [ufw(8)](https://manpages.ubuntu.com/manpages/noble/en/man8/ufw.8.html)
for more information.

## Task Execution and Structure

See [STRUCTURE.md](STRUCTURE.md) for tree of the role structure.

## Role testing

See [TESTING.md](TESTING.md).
"
echo '## Role Variables with defaults'

for variables in $(find ./defaults -type f | sort); do
  echo; echo "### $variables"
  echo
  echo '```yaml'
  grep -vE '^#|---|\.\.\.' "$variables"
  echo '```'
done

echo
echo "## Recommended Reading

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

## License

Apache License Version 2.0

## Author Information

[https://github.com/konstruktoid](https://github.com/konstruktoid \"github.com/konstruktoid\")"
} > ./README.md

{
echo "# Testing

Before running any test:
- ensure [Vagrant](https://www.vagrantup.com/),
  [VirtualBox](https://www.virtualbox.org/) and/or
  [Docker](https://www.docker.com/) is installed.
- ensure all Python [requirements](./requirements-dev.txt) are installed.
- ensure that the role is installed as \`konstruktoid.hardening\`

## Distribution boxes used by Molecule and Vagrant
"

echo '```console'
git grep -E 'box:|box =|image:' Vagrantfile molecule/ | awk '{print $NF}' |\
  tr -d '"' | sort | uniq
echo '```'

echo
echo "If the [runTests.sh](runTests.sh) script is executed as \`runTests.sh vagrant\`,
[Vagrant](https://www.vagrantup.com/ \"Vagrant\") will configure hosts and run the
\`konstruktoid.hardening\` role, it will then run
[Lynis](https://github.com/CISOfy/lynis/ \"Lynis\") and \`bats\` tests from the
[konstruktoid/hardening](https://github.com/konstruktoid/hardening \"konstruktoid/hardening\")
repository if the host is using [Ubuntu](https://ubuntu.com/ \"Ubuntu\")."

echo
echo "### tox environments
"
echo '```console'
tox -l
echo '```'
} > ./TESTING.md

rm ./*.log ./*.html ./*.list

{
echo "# Structure

"

echo '```sh'
tree .
echo '```'
} > ./STRUCTURE.md
