# Testing

Before running any test:
- ensure [QEMU](https://www.qemu.org/), `genisoimage` and OVMF, and/or
  [Docker](https://www.docker.com/) is installed.
- ensure all Python [requirements](./requirements-dev.txt) are installed.
- ensure that the role is installed as `konstruktoid.hardening`

## Scenarios

- `default` (`molecule/default`) boots AlmaLinux 10, Debian trixie and Ubuntu
  resolute cloud images directly under `qemu-system-x86_64`, with UEFI (OVMF)
  and cloud-init seed ISOs built with `genisoimage`, instead of Vagrant. The
  downloaded images are cached in `~/.cache/molecule-qemu/images`, and the
  serial console of each guest is logged to `molecule-logs/default/`. KVM is
  used when `/dev/kvm` is accessible, otherwise the guests fall back to slow
  emulation. After `molecule converge`, use `molecule login --host resolute` to
  open an SSH session to the Ubuntu guest.
- `docker` (`molecule/docker`) runs the same three platforms as containers.
  Tasks that need a real kernel or init system are skipped in containers.
- `molecule/resources` holds the playbooks shared by both scenarios: `converge.yml`,
  `prepare.yml`, `verify.yml`, and the QEMU `create_qemu.yml` and `destroy_qemu.yml`.
  The role variables for each scenario are kept in its `inventory` directory.
- Ubuntu ships `sudo-rs`, which the Ansible `sudo` become plugin cannot parse,
  so `ansible_become_exe` is set to `sudo.ws` for resolute in the `default`
  scenario, see [ansible/ansible#85837](https://github.com/ansible/ansible/issues/85837).
- On Debian trixie and forky the seccomp sandbox of APT is left off, see
  `apt_seccomp_broken_releases`.

## Images used by Molecule

```console
docker.io/almalinux:10
docker.io/debian:trixie-slim
docker.io/ubuntu:resolute
https://cloud-images.ubuntu.com/resolute/current/resolute-server-cloudimg-amd64.img
https://cloud.debian.org/images/cloud/trixie/latest/debian-13-generic-amd64.qcow2
https://repo.almalinux.org/almalinux/10/cloud/x86_64/images/AlmaLinux-10-GenericCloud-latest.x86_64.qcow2
```

### tox environments

`tox -e <name>` runs `ansible-lint` followed by `molecule test`. The `default`
(QEMU) scenario is used by `devel` and `upstream`, the `docker` scenario by
`docker` and `docker-upstream`. The `upstream` variants use unpinned upstream
`ansible-core`, `ansible-lint` and `molecule`.

```console
devel
docker
docker-upstream
upstream
```
