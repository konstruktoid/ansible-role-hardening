#!/bin/bash -l

set -o pipefail

ANSIBLE_V=2.8

export ANSIBLE_NOCOWS=1

if ! [ -x "$(command -v vagrant)" ]; then
  echo 'Vagrant is required.'
  exit 1
elif ! [ -x "$(command -v molecule)" ]; then
  echo 'Ansible Molecule is required.'
  exit 1
else
  echo "Vagrant and Ansible Molecule installed."
fi

echo "Starting basic preparations."
vagrant box update --insecure || true

echo "Copying the role."
sudo mkdir -p /etc/ansible/roles/konstruktoid.hardening/
sudo cp -R . /etc/ansible/roles/konstruktoid.hardening/
sudo rm /etc/ansible/roles/konstruktoid.hardening/{*.log,*.html,*.list}
echo "Finished basic preparations."
set +x


if [ -z "${ANSIBLE_V}" ]; then
  pip3 install ansible
else
  pip3 install ansible=="${ANSIBLE_V}"
fi

ANSIBLE_V0="$(ansible --version | grep '^ansible' | awk '{print $NF}')"
molecule test || exit 1

pip3 install --upgrade ansible

ANSIBLE_V1="$(ansible --version | grep '^ansible' | awk '{print $NF}')"
molecule test || exit 1

echo "Tested with Ansible version: $ANSIBLE_V0 and $ANSIBLE_V1"
