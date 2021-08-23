# Testing

## Distribution boxes used by Molecule and Vagrant

```console
almalinux/8
bento/centos-8
bento/debian-10
bento/ubuntu-20.04
centos-stream/20210603
debian/bullseye64
debian/contrib-testing64
generic/rhel8
impish/20210819
konstruktoid/focal-hardened
ubuntu/focal64
ubuntu/hirsute64
```

## Test examples

```shell
ansible-playbook tests/test.yml --extra-vars "sshd_admin_net=192.168.1.0/24"   -c local -i 'localhost,' -K
```

If the [runTests.sh](runTests.sh) script is executed as `runTests.sh vagrant`,
[Vagrant](https://www.vagrantup.com/ "Vagrant") will configure hosts and run the
`konstruktoid.hardening` role, it will then run
[Lynis](https://github.com/CISOfy/lynis/ "Lynis") and `bats` tests from the
[konstruktoid/hardening](https://github.com/konstruktoid/hardening "konstruktoid/hardening")
repository if the host is using [Ubuntu](https://ubuntu.com/ "Ubuntu").

### tox environments

```console
py39-ansible210
py39-ansible34
py39-ansible44
py39-ansibledevel
```
