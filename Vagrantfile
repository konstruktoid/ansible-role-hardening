$prep = <<SCRIPT
set -exu -o pipefail

echo 'export PATH=$PATH:/usr/local/bin:~/.local/bin' | tee -a /home/vagrant/.bashrc
echo 'export PATH=$PATH:/usr/local/bin:~/.local/bin' | tee -a /etc/profile
export PATH=$PATH:/usr/local/bin:~/.local/bin

if [ -x "$(which apt-get)" ]; then
  apt-get update
  apt-get install --assume-yes --no-install-recommends curl git gnupg2 \
    software-properties-common python3-apt python3-dev python3-pip python3.11-venv
else
  if [ $(grep PLATFORM_ID /etc/os-release | awk -F ':' '{print $NF}' | tr -d '[a-z]"') -lt 10 ]; then
    dnf install --assumeyes python3.11
  fi

  dnf install --assumeyes curl git python3 python3-pip python3-devel \
    python3-packaging
fi

mkdir -p /tmp/vagrant-ansible/inventory
mkdir -p /usr/share/ansible/roles

echo "localhost ansible_connection=local" | tee /tmp/vagrant-ansible/inventory/localhost_inventory
ln -sf /vagrant /usr/share/ansible/roles/konstruktoid.hardening

PYTHON_BIN="$(ls -1 $(which python3)* | grep -o 'python3.[0-9][0-9]' | sort -r | head -n 1)"
echo "${PYTHON_BIN}"

if [ ! $("${PYTHON_BIN}" -m pipx --version) ]; then
  "${PYTHON_BIN}" -m pip install pipx # --break-system-packages pipx
fi

"${PYTHON_BIN}" -m pipx ensurepath --force
"${PYTHON_BIN}" -m pipx install --global --include-deps ansible
sudo -u vagrant -i ansible-galaxy install --role-file=/vagrant/requirements.yml --force
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
    { name: "almalinux9", box: "bento/almalinux-9", python: "/usr/bin/python3.11" },
    { name: "almalinux10", box: "almalinux/10-kitten-x86_64_v2", python: "/usr/bin/python3" },
    { name: "bookworm", box: "debian/bookworm64", python: "/usr/bin/python3" },
    { name: "noble", box: "bento/ubuntu-24.04", python: "/usr/bin/python3" },
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
