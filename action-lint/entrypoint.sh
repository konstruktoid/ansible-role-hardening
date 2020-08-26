#!/bin/sh -l

if ! ansible-lint -v ./tests/test.yml; then
    echo 'ansible-lint failed.'
    exit 1
fi

if ! find ./ -type f -name '*.y*ml' ! -name '.*' -print0 | \
  xargs -0 yamllint -d "{extends: default, rules: {line-length: {level: warning}}}"; then
    echo 'yamllint failed.'
    exit 1
fi
