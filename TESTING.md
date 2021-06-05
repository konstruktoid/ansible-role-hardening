# Testing

## Distribution boxes used by Molecule and Vagrant

```yaml
bento/centos-8
bento/debian-10
bento/ubuntu-20.04
centos-stream/20210210
debian/bullseye64
debian/contrib-testing64
generic/rhel8
impish/20210603
konstruktoid/focal-hardened
ubuntu/hirsute64
```

```shell
ansible-playbook tests/test.yml --extra-vars "sshd_admin_net=192.168.1.0/24" \
  -c local -i 'localhost,' -K
```

The [runTests.sh](runTests.sh) script may be used to automatically update
current Vagrant boxes and then use [Ansible Molecule](https://molecule.readthedocs.io)
to test the default scenario on the playbook.

The following Molecule scenarios are available:

```
centos
debian
default
redhat
ubuntu
```

If the [runTests.sh](runTests.sh) is executed as `runTests.sh vagrant`,
[Vagrant](https://www.vagrantup.com/ "Vagrant") will configure hosts and run the
`konstruktoid.hardening` role, it will then run
[Lynis](https://github.com/CISOfy/lynis/ "Lynis") and `bats` tests from the
[konstruktoid/hardening](https://github.com/konstruktoid/hardening "konstruktoid/hardening")
repository if the host is using [Ubuntu](https://ubuntu.com/ "Ubuntu").

## System testing

To run a [OpenSCAP](https://github.com/ComplianceAsCode/content) test on a
CentOS host follow the instructions at
[https://copr.fedorainfracloud.org/coprs/openscapmaint/openscap-latest/](https://copr.fedorainfracloud.org/coprs/openscapmaint/openscap-latest/).

Note that many benchmarks and guidelines are missing from OpenSCAP unless the
tool is used on a RedHat server.
