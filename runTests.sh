#!/bin/bash -l

set -o pipefail

export ANSIBLE_NOCOWS=1

if ! [ -x "$(command -v molecule)" ]; then
  echo 'Ansible Molecule is required.'
  exit 1
fi

function lint {
  echo "Linting."
  set -x

  echo "# Running ansible-lint"
  ansible-lint --version

  if ! ansible-lint --exclude .git --exclude .github --exclude tests/; then
    echo 'ansible-lint failed.'
    exit 1
  fi

  set +x
}

lint

ANSIBLE_V0="$(ansible --version | grep '^ansible' | awk '{print $NF}')"

molecule test || exit 1
echo "Tested with Ansible version: $ANSIBLE_V0"
