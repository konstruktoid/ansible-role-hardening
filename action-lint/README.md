= YAML and Ansible linting

Using `yamllint` and `ansible-lint` to check `*.y*ml` files.

== Entrypoint code

```sh
#!/bin/sh -l

if ! find ./ -type f -name '*.y*ml' ! -name '.*' -print0 | \
  xargs -0 ansible-lint -x 403; then
    echo 'ansible-lint failed.'
    exit 1
fi

if ! find ./ -type f -name '*.y*ml' ! -name '.*' -print0 | \
  xargs -0 yamllint; then
    echo 'yamllint failed.'
    exit 1
fi
```
