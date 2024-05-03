Vagrant.configure("2") do |config|
  config.vbguest.installer_options = { allow_kernel_upgrade: false }
  config.vbguest.auto_update = false
  config.vm.provider "virtualbox" do |vb|
    vb.customize ["modifyvm", :id, "--uart1", "0x3F8", "4"]
    vb.customize ["modifyvm", :id, "--uartmode1", "disconnected"]
  end

  config.vm.define "bullseye_vlan" do |bullseye_vlan|
    bullseye_vlan.vm.box = "debian/bullseye64"
    bullseye_vlan.ssh.insert_key = true
    bullseye_vlan.vm.hostname = "bullseye-vlan"
    bullseye_vlan.vm.boot_timeout = 600
    bullseye_vlan.vm.provision "shell",
      inline: "ip link set dev eth0 down; ip link set eth0 name eth0.101; ip link set dev eth0.101 up; dhclient -r eth0.101; dhclient eth0.101"
    bullseye_vlan.vm.provision "shell",
      inline: "apt-get update && apt-get -y install curl python3-pip && python3 -m pip install ansible"
    bullseye_vlan.vm.provision "ansible" do |a|
      a.verbose = "v"
      a.limit = "all"
      a.playbook = "tests/test.yml"
      a.extra_vars = {
        "ansible_become_pass" => "vagrant",
        "ansible_python_interpreter" => "/usr/bin/python3",
        "sshd_admin_net" => ["0.0.0.0/0"],
        "sshd_allow_groups" => ["vagrant", "sudo", "debian", "ubuntu"],
        "system_upgrade" => "false",
        "manage_aide" => "false",
      }
    end
  end

  config.vm.define "bullseye" do |bullseye|
    bullseye.vm.box = "debian/bullseye64"
    bullseye.ssh.insert_key = true
    bullseye.vm.hostname = "bullseye"
    bullseye.vm.boot_timeout = 600
    bullseye.vm.provision "shell",
      inline: "apt-get update && apt-get -y install curl python3-pip && python3 -m pip install ansible"
    bullseye.vm.provision "ansible" do |a|
      a.verbose = "v"
      a.limit = "all"
      a.playbook = "tests/test.yml"
      a.extra_vars = {
        "ansible_become_pass" => "vagrant",
        "ansible_python_interpreter" => "/usr/bin/python3",
        "sshd_admin_net" => ["0.0.0.0/0"],
        "sshd_allow_groups" => ["vagrant", "sudo", "debian", "ubuntu"],
        "system_upgrade" => "false",
     }
    end
  end

  config.vm.define "bookworm" do |bookworm|
    bookworm.vm.box = "debian/bookworm64"
    bookworm.ssh.insert_key = true
    bookworm.vm.hostname = "bookworm"
    bookworm.vm.boot_timeout = 600
    bookworm.vm.provision "shell",
    # Remove EXTERNALLY-MANAGED to ignore PEP 668
      inline: "apt-get update && apt-get -y install python3-pip curl && rm -rf /usr/lib/python3.11/EXTERNALLY-MANAGED && python3 -m pip install ansible"
    bookworm.vm.provision "ansible" do |a|
      a.verbose = "v"
      a.limit = "all"
      a.playbook = "tests/test.yml"
      a.extra_vars = {
        "ansible_become_pass" => "vagrant",
        "ansible_python_interpreter" => "/usr/bin/python3",
        "sshd_admin_net" => ["0.0.0.0/0"],
        "sshd_allow_groups" => ["vagrant", "sudo", "debian", "ubuntu"],
        "system_upgrade" => "false",
     }
    end
  end

  config.vm.define "jammy" do |jammy|
    jammy.vm.box = "bento/ubuntu-22.04"
    jammy.ssh.insert_key = true
    jammy.vm.hostname = "jammy"
    jammy.vm.boot_timeout = 600
    jammy.vm.provision "shell",
      inline: "apt-get update && apt-get -y install curl python3-pip && python3 -m pip install ansible"
    jammy.vm.provision "ansible" do |a|
      a.verbose = "v"
      a.limit = "all"
      a.playbook = "tests/test.yml"
      a.extra_vars = {
        "sshd_admin_net" => ["0.0.0.0/0"],
        "sshd_allow_groups" => ["vagrant", "sudo", "ubuntu"],
        "ansible_python_interpreter" => "/usr/bin/python3",
      }
     end
   end

  config.vm.define "noble" do |noble|
    noble.vm.box = "bento/ubuntu-24.04"
    noble.ssh.insert_key = true
    noble.vm.hostname = "noble"
    noble.vm.boot_timeout = 600
    noble.vm.provision "shell",
    # Ignore PEP 668
      inline: "apt-get update && apt-get -y install python3-pip curl && python3 -m pip install --break-system-packages ansible"
    noble.vm.provision "ansible" do |a|
      a.verbose = "v"
      a.limit = "all"
      a.playbook = "tests/test.yml"
      a.extra_vars = {
        "sshd_admin_net" => ["0.0.0.0/0"],
        "sshd_allow_groups" => ["vagrant", "sudo", "ubuntu"],
        "ansible_python_interpreter" => "/usr/bin/python3",
      }
     end
   end

  config.vm.define "almalinux" do |almalinux|
    almalinux.vm.box = "almalinux/9"
    almalinux.ssh.insert_key = true
    almalinux.vm.provider "virtualbox" do |c|
      c.default_nic_type = "82543GC"
      c.memory = 2048
    end
    almalinux.vm.hostname = "almalinux"
    almalinux.vm.provision "shell",
      inline: "dnf clean all && dnf install -y curl python3-pip && python3 -m pip install -U pip && python3 -m pip install ansible"
    almalinux.vm.provision "ansible" do |a|
      a.verbose = "v"
      a.limit = "all"
      a.playbook = "tests/test.yml"
      a.extra_vars = {
        "sshd_admin_net" => ["0.0.0.0/0"],
        "sshd_allow_groups" => ["vagrant", "sudo"],
        "ansible_python_interpreter" => "/usr/bin/python3",
      }
    end
  end
end
