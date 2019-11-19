Vagrant.configure("2") do |config|
  config.vm.provider "virtualbox" do |v|
    v.default_nic_type = "Am79C973"
  end

  config.vm.define "bionic" do |bionic|
    bionic.vm.box = "ubuntu/bionic64"
    bionic.ssh.insert_key = true
    bionic.vm.network "private_network", ip: "10.2.3.41"
    bionic.vm.hostname = "bionic"
    bionic.vm.provision "shell",
      inline: "apt-get update && apt-get -y install ansible aptitude dnsmasq python python-pexpect --no-install-recommends"
    bionic.vm.provision "ansible" do |a|
      a.verbose = "v"
      a.limit = "all"
      a.playbook = "tests/test.yml"
      a.extra_vars = {
        "sshd_admin_net" => "0.0.0.0/0",
        "sshd_allow_groups" => "vagrant sudo ubuntu"
     }
    end
  end

  config.vm.define "buster" do |buster|
    buster.vm.box = "bento/debian-10"
    buster.ssh.insert_key = true
    buster.vm.network "private_network", ip: "10.2.3.42"
    buster.vm.hostname = "buster"
    buster.vm.provision "shell",
      inline: "apt-get update && apt-get -y install ansible aptitude dnsmasq python python-pexpect --no-install-recommends"
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
      inline: "dnf install -y epel-release && dnf install -y ansible python3"
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

  config.vm.define "fedora" do |fedora|
    fedora.vm.box = "bento/fedora-30"
    fedora.ssh.insert_key = true
    fedora.vm.network "private_network", ip: "10.2.3.44"
    fedora.vm.hostname = "fedora"
    fedora.vm.provision "shell",
      inline: "dnf install -y ansible"
    fedora.vm.provision "ansible" do |a|
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

  config.vm.define "disco" do |disco|
    disco.vm.box = "ubuntu/disco64"
    disco.ssh.insert_key = true
    disco.vm.network "private_network", ip: "10.2.3.45"
    disco.vm.hostname = "disco"
    disco.vm.provision "shell",
      inline: "apt-get update && apt-get -y install ansible python3-pexpect --no-install-recommends"
    # disco.vm.provision "shell", path: "provision/setup.sh"
    disco.vm.provision "ansible" do |a|
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

   config.vm.define "eoan" do |eoan|
     eoan.vm.box = "ubuntu/eoan64"
     eoan.ssh.insert_key = true
     eoan.vm.network "private_network", ip: "10.2.3.46"
     eoan.vm.hostname = "eoan"
     eoan.vm.boot_timeout = 600
     eoan.vm.provision "shell",
       inline: "apt-get update && apt-get -y install ansible aptitude dnsmasq python3 python3-pexpect --no-install-recommends"
     eoan.vm.provision "ansible" do |a|
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
