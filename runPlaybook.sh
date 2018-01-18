#!/bin/sh

if ! [ -x "$(which vagrant)" ]; then
  echo 'Vagrant is required.'
fi

find ./ -type f -name '*.y*ml' | while IFS= read -r FILE; do yamllint "$FILE"; done

if pwd | grep 'ansible-role-hardening' && grep 'konstruktoid/ansible-role-hardening.git' .git/config 2>/dev/null 1>&2; then
  if [ -d '/etc/ansible/roles/konstruktoid.hardening/' ]; then
    sudo rm -rf /etc/ansible/roles/konstruktoid.hardening/
    sudo mkdir -p /etc/ansible/roles/konstruktoid.hardening/
    sudo cp -R . /etc/ansible/roles/konstruktoid.hardening/
  else
    exit 1
  fi
fi

vagrant box update
vagrant destroy -f

vagrant status | grep virtualbox | awk '{print $1}' | while IFS= read -r VM; do
  vagrant up "$VM"
  vagrant provision "$VM"
  vagrant reload "$VM"
done
