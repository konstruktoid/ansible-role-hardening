# YAML and Ansible linting

Using `ansible-lint` to check `*.y*ml` files. Note that ansible-lint knows to
also run `yamllint`, so you do not ned to run that one separately.

## Entrypoint code

```console
#!/bin/sh -l

echo "# Running ansible-lint"
ansible-lint --version

if ! ansible-lint --exclude .git --exclude .github --exclude tests/ -vv; then
  echo 'ansible-lint failed.'
  exit 1
fi
```
