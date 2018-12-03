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
      inline: "apt-get update && apt-get -y install ansible aptitude dnsmasq python --no-install-recommends"
    bionic.vm.provision "ansible" do |a|
      a.verbose = "v"
      a.limit = "all"
      a.playbook = "tests/test.yml"
      a.extra_vars = {
        "sshd_admin_net" => "0.0.0.0/0",
        "ssh_allow_groups" => "vagrant sudo ubuntu"
     }
    end
  end

  config.vm.define "stretch" do |stretch|
    stretch.vm.box = "bento/debian-9"
    stretch.ssh.insert_key = true
    stretch.vm.network "private_network", ip: "10.2.3.42"
    stretch.vm.hostname = "stretch"
    stretch.vm.provision "shell",
      inline: "apt-get update && apt-get -y install ansible aptitude dnsmasq python --no-install-recommends"
    stretch.vm.provision "ansible" do |a|
      a.verbose = "v"
      a.limit = "all"
      a.playbook = "tests/test.yml"
      a.extra_vars = {
        "sshd_admin_net" => "0.0.0.0/0",
        "ssh_allow_groups" => "vagrant sudo debian ubuntu"
     }
    end
  end

  config.vm.define "centos" do |centos|
    centos.vm.box = "bento/centos-7"
    centos.ssh.insert_key = true
    centos.vm.network "private_network", ip: "10.2.3.43"
    centos.vm.hostname = "centos"
    centos.vm.provision "shell",
      inline: "yum install -y ansible"
    centos.vm.provision "ansible" do |a|
      a.verbose = "v"
      a.limit = "all"
      a.playbook = "tests/test.yml"
      a.extra_vars = {
        "sshd_admin_net" => "0.0.0.0/0",
        "ssh_allow_groups" => "vagrant sudo"
      }
    end
  end

  config.vm.define "fedora29" do |fedora29|
    fedora29.vm.box = "generic/fedora29"
    fedora29.ssh.insert_key = true
    fedora29.vm.network "private_network", ip: "10.2.3.44"
    fedora29.vm.hostname = "fedora29"
    fedora29.vm.provision "shell",
      inline: "dnf install -y ansible"
    fedora29.vm.provision "ansible" do |a|
      a.verbose = "v"
      a.limit = "all"
      a.playbook = "tests/test.yml"
      a.extra_vars = {
        "sshd_admin_net" => "0.0.0.0/0",
        "ssh_allow_groups" => "vagrant sudo",
        "ansible_python_interpreter" => "/usr/bin/python3"
      }
    end
  end

  config.vm.define "cosmic" do |cosmic|
    cosmic.vm.box = "ubuntu/cosmic64"
    cosmic.ssh.insert_key = true
    cosmic.vm.network "private_network", ip: "10.2.3.45"
    cosmic.vm.hostname = "cosmic"
    cosmic.vm.provision "shell", path: "provision/setup.sh"
    cosmic.vm.provision "ansible" do |a|
      a.verbose = "v"
      a.limit = "all"
      a.playbook = "tests/test.yml"
      a.extra_vars = {
        "sshd_admin_net" => "0.0.0.0/0",
        "ssh_allow_groups" => "vagrant sudo ubuntu"
     }
    end
  end

  config.vm.define "disco" do |disco|
    disco.vm.box = "ubuntu/disco64"
    disco.ssh.insert_key = true
    disco.vm.network "private_network", ip: "10.2.3.47"
    disco.vm.hostname = "disco"
    disco.vm.provision "shell",
      inline: "apt-get update && apt-get -y install ansible --no-install-recommends"
    # disco.vm.provision "shell", path: "provision/setup.sh"
    disco.vm.provision "ansible" do |a|
      a.verbose = "v"
      a.limit = "all"
      a.playbook = "tests/test.yml"
      a.extra_vars = {
        "sshd_admin_net" => "0.0.0.0/0",
        "ssh_allow_groups" => "vagrant sudo ubuntu",
        "ansible_python_interpreter" => "/usr/bin/python3"
     }
    end
  end
end
