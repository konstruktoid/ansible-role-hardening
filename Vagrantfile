Vagrant.configure("2") do |config|

  config.vm.define "xenial" do |xenial|
    xenial.vm.box = "bento/ubuntu-16.04"
    xenial.ssh.insert_key = true
    xenial.vm.network "private_network", ip:"10.2.3.41"
    xenial.vm.hostname = "xenial"
    xenial.vm.provision "shell",
      inline: "apt-get update && apt-get -y install ansible aptitude dnsmasq python --no-install-recommends"
    xenial.vm.provision "ansible" do |p|
      p.verbose = "v"
      p.limit = "all"
      p.playbook = "tests/test.yml"
      p.extra_vars = {
        "sshd_admin_net" => "0.0.0.0/0",
        "ssh_allow_groups" => "vagrant sudo ubuntu"
     }
    end
  end

  config.vm.define "artful" do |artful|
    artful.vm.box = "bento/ubuntu-17.10"
    artful.ssh.insert_key = true
    artful.vm.network "private_network", ip:"10.2.3.47"
    artful.vm.hostname = "artful"
    artful.vm.provision "shell",
      inline: "apt-get update && apt-get -y install ansible aptitude dnsmasq python --no-install-recommends"
    artful.vm.provision "ansible" do |p|
      p.verbose = "v"
      p.limit = "all"
      p.playbook = "tests/test.yml"
      p.extra_vars = {
        "sshd_admin_net" => "0.0.0.0/0",
        "ssh_allow_groups" => "vagrant sudo ubuntu"
     }
    end
  end

  config.vm.define "bionic" do |bionic|
    bionic.vm.box = "ubuntu/bionic64"
    bionic.ssh.insert_key = true
    bionic.vm.network "private_network", ip:"10.2.3.48"
    bionic.vm.hostname = "bionic"
    bionic.vm.provision "shell",
      inline: "apt-get update && apt-get -y install ansible aptitude dnsmasq python --no-install-recommends"
    bionic.vm.provision "ansible" do |p|
      p.verbose = "v"
      p.limit = "all"
      p.playbook = "tests/test.yml"
      p.extra_vars = {
        "sshd_admin_net" => "0.0.0.0/0",
        "ssh_allow_groups" => "vagrant sudo ubuntu"
     }
    end
  end

  config.vm.define "stretch" do |stretch|
    stretch.vm.box = "bento/debian-9"
    stretch.ssh.insert_key = true
    stretch.vm.network "private_network", ip:"10.2.3.46"
    stretch.vm.hostname = "stretch"
    stretch.vm.provision "shell",
      inline: "apt-get update && apt-get -y install ansible aptitude dnsmasq python --no-install-recommends"
    stretch.vm.provision "ansible" do |p|
      p.verbose = "v"
      p.limit = "all"
      p.playbook = "tests/test.yml"
      p.extra_vars = {
        "sshd_admin_net" => "0.0.0.0/0",
        "ssh_allow_groups" => "vagrant sudo debian ubuntu"
     }
    end
  end

  config.vm.define "centos" do |centos|
    centos.vm.box = "bento/centos-7"
    centos.ssh.insert_key = true
    centos.vm.network "private_network", ip:"10.2.3.43"
    centos.vm.hostname = "centos"
    centos.vm.provision "ansible" do |p|
      p.verbose = "v"
      p.limit = "all"
      p.playbook = "tests/test.yml"
      p.extra_vars = {
        "sshd_admin_net" => "0.0.0.0/0",
        "ssh_allow_groups" => "vagrant sudo"
      }
    end
  end

  config.vm.define "fedora" do |fedora|
    fedora.vm.box = "bento/fedora-27"
    fedora.ssh.insert_key = true
    fedora.vm.network "private_network", ip:"10.2.3.44"
    fedora.vm.hostname = "fedora"
    fedora.vm.provision "shell",
      inline: "dnf install -y ansible"
    fedora.vm.provision "ansible" do |p|
      p.verbose = "v"
      p.limit = "all"
      p.playbook = "tests/test.yml"
      p.extra_vars = {
        "sshd_admin_net" => "0.0.0.0/0",
        "ssh_allow_groups" => "vagrant sudo"
      }
    end
  end
end
