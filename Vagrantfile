Vagrant.configure("2") do |config|

  config.vm.define "xenial" do |xenial|
    xenial.vm.box = "ubuntu/xenial64"
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

  config.vm.define "yakkety" do |yakkety|
    yakkety.vm.box = "ubuntu/yakkety64"
    yakkety.ssh.insert_key = true
    yakkety.vm.network "private_network", ip:"10.2.3.42"
    yakkety.vm.hostname = "yakkety"
    yakkety.vm.provision "shell",
      inline: "apt-get update && apt-get -y install ansible aptitude dnsmasq python --no-install-recommends"
    yakkety.vm.provision "ansible" do |p|
      p.verbose = "v"
      p.limit = "all"
      p.playbook = "tests/test.yml"
      p.extra_vars = {
        "sshd_admin_net" => "0.0.0.0/0",
        "ssh_allow_groups" => "vagrant sudo ubuntu"
     }
    end
  end

  config.vm.define "zesty" do |zesty|
    zesty.vm.box = "ubuntu/zesty64"
    zesty.ssh.insert_key = true
    zesty.vm.network "private_network", ip:"10.2.3.45"
    zesty.vm.hostname = "zesty"
    zesty.vm.provision "shell",
      inline: "apt-get update && apt-get -y install ansible aptitude dnsmasq python --no-install-recommends"
    zesty.vm.provision "ansible" do |p|
      p.verbose = "v"
      p.limit = "all"
      p.playbook = "tests/test.yml"
      p.extra_vars = {
        "sshd_admin_net" => "0.0.0.0/0",
        "ssh_allow_groups" => "vagrant sudo ubuntu"
     }
    end
  end

  config.vm.define "jessie" do |jessie|
    jessie.vm.box = "debian/jessie64"
    jessie.ssh.insert_key = true
    jessie.vm.network "private_network", ip:"10.2.3.46"
    jessie.vm.hostname = "jessie"
    jessie.vm.provision "shell",
      inline: "apt-get update && apt-get -y install ansible aptitude dnsmasq python --no-install-recommends"
    jessie.vm.provision "ansible" do |p|
      p.verbose = "v"
      p.limit = "all"
      p.playbook = "tests/test.yml"
      p.extra_vars = {
        "sshd_admin_net" => "0.0.0.0/0",
        "ssh_allow_groups" => "vagrant sudo ubuntu"
     }
    end
  end

  config.vm.define "centos" do |centos|
    centos.vm.box = "centos/7"
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
    fedora.vm.box = "fedora/25-cloud-base"
    fedora.ssh.insert_key = true
    fedora.vm.network "private_network", ip:"10.2.3.44"
    fedora.vm.hostname = "fedora"
    fedora.vm.provision "shell",
      inline: "dnf install -y python26 ansible python2-dnf"
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
