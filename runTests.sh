#!/bin/bash -l
# shellcheck disable=SC2013

set -o pipefail

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

function lint {
  echo "Linting."
  set -x

  echo "# Running ansible-lint"
  ansible-lint --version

  if ! ansible-lint --exclude .git --exclude .github --exclude tests/ -vv; then
    echo 'ansible-lint failed.'
    exit 1
  fi

  set +x
}

function prep {
  echo "Starting basic preparations."
  vagrant box update --insecure || true
  echo "Copying the role."
  set -x
  sudo mkdir -p /etc/ansible/roles/konstruktoid.hardening/
  sudo cp -R ./* /etc/ansible/roles/konstruktoid.hardening/
  sudo rm /etc/ansible/roles/konstruktoid.hardening/{*.log,*.html,*.list}
  set +x
  echo "Finished basic preparations."
}

if [ "$1" == "prep" ]; then
  prep
  exit
fi

lint

ANSIBLE_V0="$(ansible --version | grep '^ansible' | awk '{print $NF}')"

if [ "$1" == "vagrant" ]; then
  prep

  grep config.vm.define Vagrantfile | grep -o '".*"' | tr -d '"' | while read -r v; do
    vagrant up "${v}"
  done

  wait

  grep config.vm.define Vagrantfile | grep -o '".*"' | tr -d '"' | while read -r v; do
    vagrant reload "${v}"
  done

  wait

  VMFILE="$(mktemp)"
  vagrant status | grep 'running.*virtualbox' | awk '{print $1}' >> "${VMFILE}"

  for VM in $(grep -v '^#' "${VMFILE}"); do
    echo "Copying postChecks.sh to ${VM}."
    # vagrant scp <local_path> [vm_name]:<remote_path>
    vagrant scp ./postChecks.sh "${VM}":~/postChecks.sh

    echo "Rebooting ${VM}."
    vagrant ssh "${VM}" -c 'sudo -i reboot'

    SLEEP_COUNT=0
    while ! vagrant ssh "${VM}" -c 'id' && [ ${SLEEP_COUNT} -le 9 ]; do
        echo "Waiting for ${VM}."
        sleep 10
        ((SLEEP_COUNT++))
    done

    vagrant reload "${VM}"

    SLEEP_COUNT=0
    while ! vagrant ssh "${VM}" -c 'id' && [ ${SLEEP_COUNT} -le 9 ]; do
        echo "Waiting for ${VM}."
        sleep 10
        ((SLEEP_COUNT++))
    done

    echo "Running postChecks.sh."
    vagrant ssh "${VM}" -c 'sh ~/postChecks.sh || exit 1 && cat ~/lynis-report.dat' > "${VM}-$(date +%y%m%d)-lynis.log"

    echo "Saving suid.list."
    vagrant ssh "${VM}" -c 'cat ~/suid.list' >> "$(date +%y%m%d)-suid.list"

    echo "Saving bats results."
    vagrant ssh "${VM}" -c 'cat ~/bats.log' | grep 'not ok'  > "${VM}-$(date +%y%m%d)-bats.log"

    echo "Saving OpenSCAP reports."
    vagrant scp "${VM}:*.html" "."
  done

  rm "${VMFILE}"

  curl -sSL https://raw.githubusercontent.com/konstruktoid/ansible-role-hardening/master/defaults/main/suid_sgid_blocklist.yml | grep '  - ' >> "$(date +%y%m%d)-suid.list"

  if command -v dos2unix; then
    dos2unix ./*.list
  fi

  printf '\n\n'

  find ./ -name '*-lynis.log' -type f | while read -r f; do
    if test -s "$f"; then
      echo "$f:"
      grep -E '^hardening_index|^ansible_version' "$f"
    else
      echo "$f is empty, a test stage failed."
    fi
  done

  grep -iE 'warn.*\[]|sugg.*\[]' ./*-lynis.log | sed 's/-.*-lynis.log:/: /g' |\
    sort | uniq > "$(date +%y%m%d)-warnings-suggestions.log"

  grep 'not ok' ./*-bats.log | sed 's/-.*:/: /g' | sort -r | uniq > "$(date +%y%m%d)-not-ok.log"

else
  molecule test || exit 1
  echo "Tested with Ansible version: $ANSIBLE_V0"
fi
