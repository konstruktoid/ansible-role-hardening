#!/bin/sh -l

echo "# Running ansible-lint"
ansible-lint --version

mkdir -p /etc/ansible/roles/
ln -s "$(pwd)" /etc/ansible/roles/konstruktoid.hardening

if ! ansible-lint -vv ./tests/test.yml; then
    echo 'ansible-lint failed.'
    exit 1
fi

echo "# Running yamllint"
yamllint --version

if ! find ./ -type f -name '*.y*ml' ! -name '.*' -print0 | \
  xargs -0 yamllint -d "{extends: default, rules: {line-length: {level: warning}}}"; then
    echo 'yamllint failed.'
    exit 1
fi
