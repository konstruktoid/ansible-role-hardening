# Testing

Before running any test:
- ensure [Vagrant](https://www.vagrantup.com/),
  [VirtualBox](https://www.virtualbox.org/) and/or
  [Docker](https://www.docker.com/) is installed.
- ensure all Python [requirements](./requirements-dev.txt) are installed.
- ensure that the role is installed as `konstruktoid.hardening`

## Distribution boxes used by Molecule and Vagrant

```console
almalinux/10-kitten-x86_64_v2
bento/almalinux-9
bento/ubuntu-22.04
bento/ubuntu-24.04
debian/bookworm64
debian/testing64
docker.io/almalinux:9
docker.io/debian:bookworm
docker.io/ubuntu:noble
konstruktoid/ubuntu-25.04
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
py312-ansible11
py312-ansibledevel
py313-ansible11
py313-ansibledevel
```
