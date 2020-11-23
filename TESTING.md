# Testing

## Distribution boxes used by Molecule and Vagrant

```yaml
bento/centos-8
bento/debian-10
bento/ubuntu-20.04
ubuntu/groovy64
```

```shell
ansible-playbook tests/test.yml --extra-vars "sshd_admin_net=192.168.1.0/24" \
  -c local -i 'localhost,' -K
```

For running a playbook cycle suitable for performing benchmark testing,
`molecule test --scenario-name benchmark` should be used.

The [runTests.sh](runTests.sh) script may be used to automatically update
current Vagrant boxes and then use [Ansible Molecule](https://molecule.readthedocs.io)
to test the default scenario on the playbook.

If the [runTests.sh](runTests.sh) is executed as `runTests.sh vagrant`,
[Vagrant](https://www.vagrantup.com/ "Vagrant") will configure hosts and run the
`konstruktoid.hardening` role, it will then run
[Lynis](https://github.com/CISOfy/lynis/ "Lynis") and `bats` tests from the
[konstruktoid/hardening](https://github.com/konstruktoid/hardening "konstruktoid/hardening")
repository if the host is using [Ubuntu](https://ubuntu.com/ "Ubuntu").

## System testing

To run a [OpenSCAP](https://github.com/ComplianceAsCode/content) test on a
CentOS host using the included Vagrantfile follow the instructions on
[https://copr.fedorainfracloud.org/coprs/openscapmaint/openscap-latest/](https://copr.fedorainfracloud.org/coprs/openscapmaint/openscap-latest/).

```shell
curl -SsL https://copr.fedorainfracloud.org/coprs/openscapmaint/openscap-latest/repo/epel-8/openscapmaint-openscap-latest-epel-8.repo | \
  sudo tee -a /etc/yum.repos.d/openscapmaint-openscap-latest-epel-8.repo
sudo dnf install -y openscap-scanner scap-security-guide
oscap info --fetch-remote-resources /usr/share/xml/scap/ssg/content/ssg-centos8-ds.xml
sudo oscap xccdf eval --fetch-remote-resources \
  --profile xccdf_org.ssgproject.content_profile_pci-dss \
  --report fedora_pci-report.html /usr/share/xml/scap/ssg/content/ssg-centos8-ds.xml
```

To run a [OpenSCAP](https://github.com/ComplianceAsCode/content) test on a
Debian 10 host, where `v0.1.53` should be replaced with the latest available
version:

```shell
sudo apt-get -y install libopenscap8 unzip
wget https://github.com/ComplianceAsCode/content/releases/download/v0.1.53/scap-security-guide-0.1.53.zip
unzip scap-security-guide-0.1.53.zip
cd scap-security-guide-0.1.53
oscap info --fetch-remote-resources ./ssg-debian10-ds.xml
sudo oscap xccdf eval --fetch-remote-resources \
  --profile xccdf_org.ssgproject.content_profile_anssi_np_nt28_high
  --report ../buster_anssi-report.html ./ssg-debian10-ds.xml
```
