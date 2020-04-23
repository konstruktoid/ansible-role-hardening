#!/bin/bash -l
# shellcheck disable=SC2013

set -o pipefail

function lint {
  echo "Linting."
  set -x

  if ! find ./ -type f -name '*.y*ml' ! -name '.*' -print0 | \
    xargs -0 ansible-lint -x 403 -x 204; then
      echo 'ansible-lint failed.'
      exit 1
  fi

  if ! find ./ -type f -name '*.y*ml' ! -name '.*' -print0 | \
    xargs -0 yamllint -d "{extends: default, rules: {line-length: {level: warning}}}"; then
      echo 'yamllint failed.'
      exit 1
  fi
  set +x
}

if ! [ -x "$(command -v vagrant)" ]; then
  echo 'Vagrant is required.'
fi

export ANSIBLE_NOCOWS=1
ANSIBLE_V=2.8

if [ -z "$ANSIBLE_V" ]; then
  pip3 install ansible
else
  pip3 install ansible=="$ANSIBLE_V"
fi

echo "Using $(ansible --version | grep '^ansible')"

if [ "$1" = "prep" ]; then
  echo "Starting basic preparations."
  vagrant box update --insecure || true
  vagrant destroy --force

  sudo mkdir -p /etc/ansible/roles/konstruktoid.hardening/
  sudo cp -R . /etc/ansible/roles/konstruktoid.hardening/
  lint
  echo "Finished basic preparations. Exiting."
  exit
fi

lint

if [ -z "$1" ] ; then
  vagrant up
else
  vagrant up "$@"
fi

wait

VMFILE="$(mktemp)"
vagrant status | grep 'running.*virtualbox' | awk '{print $1}' >> "$VMFILE"

for VM in $(grep -v '^#' "$VMFILE"); do
  echo "Copying checkScore.sh to $VM."
  vagrant ssh "$VM" -c 'cp /vagrant/checkScore.sh ~/'
  echo "Rebooting $VM."
  vagrant ssh "$VM" -c 'sudo reboot'

  while ! vagrant ssh "$VM" -c 'id'; do
    echo "Waiting for $VM."
    sleep 10
  done

  vagrant ssh "$VM" -c 'sh ~/checkScore.sh || exit 1 && cat ~/lynis-report.dat' > "$VM-$(date +%y%m%d)-lynis.log"
done

rm "$VMFILE"

printf '\n\n'

find ./ -name '*-lynis.log' -type f | while read -r f; do
  if test -s "$f"; then
    echo "$f:"
    grep -E '^hardening_index|^ansible_version' "$f"
  else
    echo "$f is empty, a test stage failed."
  fi
done
