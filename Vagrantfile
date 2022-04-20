Vagrant.configure("2") do |config|
  config.vbguest.installer_options = { allow_kernel_upgrade: true }
  config.vm.provider "virtualbox" do |vb|
    vb.customize ["modifyvm", :id, "--uart1", "0x3F8", "4"]
    vb.customize ["modifyvm", :id, "--uartmode1", "file", File::NULL]
  end

  config.vm.define "bullseye" do |bullseye|
    bullseye.vm.box = "debian/bullseye64"
    bullseye.ssh.insert_key = true
    bullseye.vm.hostname = "bullseye"
    bullseye.vm.boot_timeout = 600
    bullseye.vbguest.auto_update = false
    bullseye.vm.provision "shell",
      inline: "apt-get update && apt-get -y install python3-pip && pip3 install ansible"
    bullseye.vm.provision "ansible" do |a|
      a.verbose = "v"
      a.limit = "all"
      a.playbook = "tests/test.yml"
      a.extra_vars = {
        "ansible_become_pass" => "vagrant",
        "ansible_python_interpreter" => "/usr/bin/python3",
        "sshd_admin_net" => "0.0.0.0/0",
        "sshd_allow_groups" => "vagrant sudo debian ubuntu",
        "system_upgrade" => "no",
        "install_aide" => "false"
     }
    end
  end

  config.vm.define "focal" do |focal|
    focal.vm.box = "ubuntu/focal64"
    focal.ssh.insert_key = true
    focal.vm.hostname = "focal"
    focal.vm.boot_timeout = 600
    focal.vm.provision "shell",
      inline: "apt-get update && apt-get -y install python3-pip && pip3 install ansible"
    focal.vm.provision "ansible" do |a|
      a.verbose = "v"
      a.limit = "all"
      a.playbook = "tests/test.yml"
      a.extra_vars = {
        "sshd_admin_net" => "0.0.0.0/0",
        "sshd_allow_groups" => "vagrant sudo ubuntu",
        "ansible_python_interpreter" => "/usr/bin/python3",
        "install_aide" => "false"
      }
     end
   end

  config.vm.define "almalinux" do |almalinux|
    almalinux.vm.box = "almalinux/8"
    almalinux.ssh.insert_key = true
    almalinux.vbguest.auto_update = false
    almalinux.vm.provider "virtualbox" do |c|
      c.default_nic_type = "82543GC"
    end
    almalinux.vm.hostname = "almalinux"
    almalinux.vm.provision "shell",
      inline: "dnf clean all && dnf install -y python3-pip && pip3 install -U pip && pip3 install ansible"
    almalinux.vm.provision "ansible" do |a|
      a.verbose = "v"
      a.limit = "all"
      a.playbook = "tests/test.yml"
      a.extra_vars = {
        "sshd_admin_net" => "0.0.0.0/0",
        "sshd_allow_groups" => "vagrant sudo",
        "ansible_python_interpreter" => "/usr/bin/python3",
        "install_aide" => "false"
      }
    end
  end
end
