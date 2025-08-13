#!/bin/bash

set -euo pipefail

PYTHON_LIB_PATH="$(python3 -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')"

echo "ANSIBLE_FILTER_PLUGINS: ${PYTHON_LIB_PATH}/molecule/provisioner/ansible/plugins/filter:${HOME}/.ansible/plugins/filter:/usr/share/ansible/plugins/filter
ANSIBLE_LIBRARY: ${PYTHON_LIB_PATH}/molecule/provisioner/ansible/plugins/modules:${PYTHON_LIB_PATH}/molecule_plugins/vagrant/modules:${HOME}/.ansible/plugins/modules:/usr/share/ansible/plugins/modules"
