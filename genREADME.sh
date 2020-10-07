#!/bin/sh

if [ -z "${ANSIBLE_V}" ]; then
  ANSIBLE_V=2.9
else
  ANSIBLE_V="${ANSIBLE_V}"
fi

{
echo "# ansible-role-hardening

An [Ansible](https://www.ansible.com/) role to make a CentOS, Debian or Ubuntu
server a bit more secure,
[systemd edition](https://freedesktop.org/wiki/Software/systemd/).

Requires Ansible >= ${ANSIBLE_V}.

Available on
[Ansible Galaxy](https://galaxy.ansible.com/konstruktoid/hardening).

## Distribution boxes used by Molecule and Vagrant

\`\`\`yaml"
grep -E 'box:|vm\.box' molecule/default/molecule.yml Vagrantfile |\
  grep -vE '^#|^$' | awk '{print $NF}' | tr -d '"' | sort | uniq
echo "\`\`\`

## Dependencies

None.

## Example Playbook

\`\`\`shell
---
- hosts: all
  serial: 50%
    - { role: konstruktoid.hardening, sshd_admin_net: [10.0.0.0/24] }
...
\`\`\`

## Structure

See [STRUCTURE.md](STRUCTURE.md).

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

[Center for Internet Security Linux Benchmarks](https://www.cisecurity.org/cis-benchmarks/)

[Common Configuration Enumeration](https://nvd.nist.gov/cce/index.cfm)

[DISA Security Technical Implementation Guides](https://public.cyber.mil/stigs/downloads/?_dl_facet_stigs=operating-systems%2Cunix-linux)

[SCAP Security Guides](https://static.open-scap.org/)

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
echo "# Structure

![Alt text](./images/ansible-role-hardening.svg)
<img src=\"./images/ansible-role-hardening.svg\">
"

echo '```sh'
tree .
echo '```'
} > ./STRUCTURE.md
