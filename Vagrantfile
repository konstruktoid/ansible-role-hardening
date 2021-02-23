Vagrant.configure("2") do |config|
  config.vbguest.installer_options = { allow_kernel_upgrade: true }
  config.vm.provider "virtualbox" do |vb|
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
        "sshd_allow_groups" => "vagrant sudo debian ubuntu",
        "ansible_python_interpreter" => "/usr/bin/python3"
     }
    end
  end

  config.vm.define "bullseye" do |bullseye|
    bullseye.vm.box = "debian/contrib-testing64"
    bullseye.ssh.insert_key = true
    bullseye.vm.network "private_network", ip: "10.2.3.50"
    bullseye.vm.hostname = "bullseye"
    bullseye.vm.boot_timeout = 600
    bullseye.vm.provision "shell",
      inline: "apt-get update && apt-get -y install ansible"
    bullseye.vm.provision "ansible" do |a|
      a.verbose = "v"
      a.limit = "all"
      a.playbook = "tests/test.yml"
      a.extra_vars = {
        "system_upgrade" => "no",
        "sshd_admin_net" => "0.0.0.0/0",
        "sshd_allow_groups" => "vagrant sudo debian ubuntu",
        "ansible_python_interpreter" => "/usr/bin/python3"
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

  config.vm.define "centos_stream" do |centos_stream|
    centos_stream.vm.hostname = "centos_stream"
    centos_stream.vm.box = "centos-stream/20210210"
    centos_stream.vm.box_url = "https://cloud.centos.org/centos/8-stream/x86_64/images/CentOS-Stream-Vagrant-8-20210210.0.x86_64.vagrant-virtualbox.box"
    centos_stream.ssh.insert_key = true
    centos_stream.vm.network "private_network", ip: "10.2.3.49"
    centos_stream.vm.provider "virtualbox" do |c|
      c.default_nic_type = "82543GC"
    end
    centos_stream.vm.hostname = "centosstream"
    centos_stream.vm.provision "shell",
      inline: "dnf clean all && dnf install -y epel-release && dnf install -y ansible"
    centos_stream.vm.provision "ansible" do |a|
      a.verbose = "v"
      a.limit = "all"
      a.playbook = "tests/test.yml"
      a.extra_vars = {
        "sshd_admin_net" => "0.0.0.0/0",
        "sshd_allow_groups" => "vagrant sudo",
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

  config.vm.define "focal_efi" do |focal_efi|
    focal_efi.vm.box = "konstruktoid/focal-hardened"
    focal_efi.ssh.insert_key = true
    focal_efi.vm.network "private_network", ip: "10.2.3.44"
    focal_efi.vm.hostname = "focalefi"
    focal_efi.vm.boot_timeout = 600
    focal_efi.vm.provision "shell",
      inline: "apt-get update && apt-get -y install ansible",
      upload_path: "/var/tmp/vagrant-shell"
    focal_efi.vm.provision "ansible" do |a|
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

  config.vm.define "hirsute" do |hirsute|
    hirsute.vm.box = "ubuntu/hirsute64"
    hirsute.ssh.insert_key = true
    hirsute.vm.network "private_network", ip: "10.2.3.51"
    hirsute.vm.hostname = "hirsute"
    hirsute.vm.boot_timeout = 600
    hirsute.vm.synced_folder ".", "/vagrant", disabled: true
    hirsute.vm.provision "shell",
      inline: "apt-get update && apt-get -y install ansible"
    hirsute.vm.provision "ansible" do |a|
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
