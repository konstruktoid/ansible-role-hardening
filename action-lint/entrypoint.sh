#!/bin/sh -l

echo "# Running ansible-lint"
ansible-lint --version

if ! ansible-lint --exclude .git --exclude .github --exclude tests/ -vv .; then
  echo 'ansible-lint failed.'
  exit 1
fi

echo "# Running yamllint"
yamllint --version

if ! find . -type f -name '*.y*ml' ! -name '.*' -print0 | \
  xargs -0 yamllint -d "{extends: default, rules: {line-length: {level: warning}}}"; then
    echo 'yamllint failed.'
    exit 1
fi
