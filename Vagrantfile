Vagrant.configure("2") do |config|
  config.vbguest.installer_options = { allow_kernel_upgrade: true }
  config.vm.provider "virtualbox" do |vb|
    vb.default_nic_type = "Am79C973"
    vb.memory = 2048
    vb.customize ["modifyvm", :id, "--uart1", "0x3F8", "4"]
    vb.customize ["modifyvm", :id, "--uartmode1", "file", File::NULL]
  end

  config.vm.define "buster" do |buster|
    buster.vm.box = "bento/debian-10"
    buster.ssh.insert_key = true
    buster.vm.network "private_network", ip: "10.2.3.42"
    buster.vm.hostname = "buster"
    buster.vm.boot_timeout = 600
    buster.vm.provision "shell",
      inline: "apt-get update && apt-get -y install ansible"
    buster.vm.provision "ansible" do |a|
      a.verbose = "v"
      a.limit = "all"
      a.playbook = "tests/test.yml"
      a.extra_vars = {
        "sshd_admin_net" => "0.0.0.0/0",
        "sshd_allow_groups" => "vagrant sudo debian ubuntu"
     }
    end
  end

  config.vm.define "centos" do |centos|
    centos.vm.box = "bento/centos-8"
    centos.ssh.insert_key = true
    centos.vm.network "private_network", ip: "10.2.3.43"
    centos.vm.provider "virtualbox" do |c|
      c.default_nic_type = "82543GC"
    end
    centos.vm.hostname = "centos"
    centos.vm.provision "shell",
      inline: "dnf clean all && dnf install -y epel-release && dnf install -y ansible"
    centos.vm.provision "ansible" do |a|
      a.verbose = "v"
      a.limit = "all"
      a.playbook = "tests/test.yml"
      a.extra_vars = {
        "sshd_admin_net" => "0.0.0.0/0",
        "sshd_allow_groups" => "vagrant sudo",
        "ansible_python_interpreter" => "/usr/bin/python3"
      }
    end
  end

  config.vm.define "focal" do |focal|
    focal.vm.box = "bento/ubuntu-20.04"
    focal.ssh.insert_key = true
    focal.vm.network "private_network", ip: "10.2.3.47"
    focal.vm.hostname = "focal"
    focal.vm.boot_timeout = 600
    focal.vm.provision "shell",
      inline: "apt-get update && apt-get -y install ansible"
    focal.vm.provision "ansible" do |a|
      a.verbose = "v"
      a.limit = "all"
      a.playbook = "tests/test.yml"
      a.extra_vars = {
        "sshd_admin_net" => "0.0.0.0/0",
        "sshd_allow_groups" => "vagrant sudo ubuntu",
        "ansible_python_interpreter" => "/usr/bin/python3"
      }
     end
   end

  config.vm.define "groovy" do |groovy|
    groovy.vm.box = "ubuntu/groovy64"
    groovy.ssh.insert_key = true
    groovy.vm.network "private_network", ip: "10.2.3.48"
    groovy.vm.hostname = "groovy"
    groovy.vm.boot_timeout = 600
    groovy.vm.synced_folder ".", "/vagrant", disabled: true
    groovy.vm.provision "shell",
      inline: "apt-get update && apt-get -y install ansible"
    groovy.vm.provision "ansible" do |a|
      a.verbose = "v"
      a.limit = "all"
      a.playbook = "tests/test.yml"
      a.extra_vars = {
        "sshd_admin_net" => "0.0.0.0/0",
        "sshd_allow_groups" => "vagrant sudo ubuntu",
        "ansible_python_interpreter" => "/usr/bin/python3"
      }
    end
  end
end
