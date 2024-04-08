# Testing

Before running any test:
- ensure [Vagrant](https://www.vagrantup.com/),
  [VirtualBox](https://www.virtualbox.org/) and/or
  [Docker](https://www.docker.com/) is installed.
- ensure all Python [requirements](./requirements-dev.txt) are installed.

## Distribution boxes used by Molecule and Vagrant

```console
almalinux/8
almalinux/9
bento/ubuntu-20.04
debian/bookworm64
debian/bullseye64
debian/testing64
docker.io/almalinux:9
docker.io/debian:bookworm
docker.io/ubuntu:jammy
generic/rhel8
ubuntu/focal64
ubuntu/jammy64
ubuntu/lunar64
ubuntu/mantic64
ubuntu/noble64
```

If the [runTests.sh](runTests.sh) script is executed as `runTests.sh vagrant`,
[Vagrant](https://www.vagrantup.com/ "Vagrant") will configure hosts and run the
`konstruktoid.hardening` role, it will then run
[Lynis](https://github.com/CISOfy/lynis/ "Lynis") and `bats` tests from the
[konstruktoid/hardening](https://github.com/konstruktoid/hardening "konstruktoid/hardening")
repository if the host is using [Ubuntu](https://ubuntu.com/ "Ubuntu").

### tox environments

```console
devel
py310-ansible8
py310-ansible9
py310-ansibledevel
py311-ansible8
py311-ansible9
py311-ansibledevel
```
