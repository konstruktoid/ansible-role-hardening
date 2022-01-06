#!/bin/sh -l

echo "# Running ansible-lint"
ansible-lint --version

if ! ansible-lint --exclude .git --exclude .github -vv; then
  echo 'ansible-lint failed.'
  exit 1
fi

echo "# Running yamllint"
yamllint --version

if ! yamllint -d "{extends: default, ignore: .*, rules: {line-length: {max: 120, level: warning}}}" .; then
  echo 'yamllint failed.'
  exit 1
fi
