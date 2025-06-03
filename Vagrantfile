$prep = <<SCRIPT
set -exu -o pipefail


if [ -x "$(which apt-get)" ]; then
  apt-get update
  apt-get install --assume-yes --no-install-recommends curl git gnupg2 \
    software-properties-common python3-apt python3-dev
else
  dnf install --assumeyes curl git python3-devel python3-packaging
fi

mkdir -p /tmp/vagrant-ansible/inventory
mkdir -p /usr/share/ansible/roles

echo "localhost ansible_connection=local" | tee /tmp/vagrant-ansible/inventory/localhost_inventory
ln -sf /vagrant /usr/share/ansible/roles/konstruktoid.hardening

sudo -u vagrant -i bash -c "curl -LsSf https://astral.sh/uv/install.sh | sh && \
  uv venv --python 3.11 /var/tmp/venv && \
  echo 'export PATH=/var/tmp/venv/bin:/home/vagrant/.local/bin:$PATH' | tee -a /home/vagrant/.bashrc && \
  echo 'export VIRTUAL_ENV=/var/tmp/venv' | tee -a /home/vagrant/.bashrc && \
  VIRTUAL_ENV=/var/tmp/venv uv pip install -r /vagrant/requirements-dev.txt && \
  ansible-galaxy install --role-file=/vagrant/requirements.yml --force"
SCRIPT

Vagrant.configure("2") do |config|
  config.vbguest.installer_options = { allow_kernel_upgrade: false }
  config.vbguest.auto_update = false
  config.vm.provider "virtualbox" do |vb|
    vb.customize ["modifyvm", :id, "--uart1", "0x3F8", "4"]
    vb.customize ["modifyvm", :id, "--uartmode1", "disconnected"]
    vb.memory = "2048"
  end

  hosts = [
    { name: "almalinux9", box: "bento/almalinux-9", python: "/var/tmp/venv/bin/python3" },
    { name: "almalinux10", box: "almalinux/10-kitten-x86_64_v2", python: "/var/tmp/venv/bin/python3" },
    { name: "bookworm", box: "debian/bookworm64", python: "/var/tmp/venv/bin/python3" },
    { name: "noble", box: "bento/ubuntu-24.04", python: "/var/tmp/venv/bin/python3" },
  ]

  hosts.each do |host|
    config.vm.define host[:name] do |node|
      node.vm.box = host[:box]
      node.ssh.insert_key = true
      node.ssh.key_type = "ed25519"
      node.vm.hostname = host[:name]
      node.vm.boot_timeout = 600
      node.vm.provision "shell",
        inline: $prep
      node.vm.provision "ansible_local" do |a|
        a.compatibility_mode = "2.0"
        a.extra_vars = {
          "sshd_admin_net" => ["0.0.0.0/0"],
          "sshd_allow_groups" => ["vagrant", "sudo", "ubuntu"],
          "ansible_python_interpreter" => host[:python],
        }
        a.install = false
        a.limit = "localhost"
        a.playbook = "tests/test.yml"
        a.verbose = "v"
      end
    end
  end
end
