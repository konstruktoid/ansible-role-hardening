#!/bin/sh

if ! [ -x "$(command -v vagrant)" ]; then
  echo 'Vagrant is required.'
fi

if pwd | grep 'ansible-role-hardening' && grep 'konstruktoid/ansible-role-hardening.git' .git/config 2>/dev/null 1>&2; then
  if [ -d '/etc/ansible/roles/konstruktoid.hardening/' ]; then
    if ! sudo rm -rf /etc/ansible/roles/konstruktoid.hardening/; then
      exit 1
    else
      sudo mkdir -p /etc/ansible/roles/konstruktoid.hardening/
      sudo cp -R . /etc/ansible/roles/konstruktoid.hardening/
    fi
  else
    exit 1
  fi
fi

export ANSIBLE_NOCOWS=1
ANSIBLE_V=2.5

if [ -z "$ANSIBLE_V" ]; then
  pip install --quiet ansible
else
  pip install --quiet ansible=="$ANSIBLE_V"
fi

echo "Using $(ansible --version | grep '^ansible')"

if ! find ./ -type f -name '*.y*ml' ! -name '.*' -print0 | \
  xargs -0L1 ansible-lint -x 403; then
    echo 'ansible-lint failed.'
    exit 1
fi

if ! find ./ -type f -name '*.y*ml' ! -name '.*' -print0 | xargs -0L1 yamllint; then
  echo 'yamllint failed.'
  exit 1
fi


vagrant box update --insecure
vagrant destroy --force

if [ -z "$1" ]; then
  vagrant up
else
  vagrant up "$@"
fi

wait

VMFILE="$(mktemp)"
vagrant status | grep 'running.*virtualbox' | awk '{print $1}' >> "$VMFILE"

grep -v '^#' "$VMFILE" | while read -r VM; do
  vagrant ssh "$VM" -c 'cp /vagrant/checkScore.sh ~/'
  echo "Copying checkScore.sh on $VM."
  vagrant ssh "$VM" -c 'sudo reboot'
  echo "Rebooting $VM."

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
