Vagrant.configure("2") do |config|

  config.vm.define "xenial" do |xenial|
    xenial.vm.box = "ubuntu/xenial64"
    xenial.ssh.insert_key = true
    xenial.vm.network "private_network", ip:"10.2.3.41"
    xenial.vm.hostname = "xenial"
    xenial.vm.provision "shell",
      inline: "apt-get update && apt-get -y install ansible aptitude python --no-install-recommends"
    xenial.vm.provision "ansible" do |p|
      p.verbose = "v"
      p.limit = "all"
      p.playbook = "hardening-test.yml"
      p.extra_vars = {
        "sshd_admin_net" => "0.0.0.0/0",
     }
    end
  end

  config.vm.define "centos" do |centos|
    centos.vm.box = "centos/7"
    centos.ssh.insert_key = true
    centos.vm.network "private_network", ip:"10.2.3.42"
    centos.vm.hostname = "centos"
    centos.vm.provision "ansible" do |p|
      p.verbose = "v"
      p.limit = "all"
      p.playbook = "hardening-test.yml"
      p.extra_vars = {
        "sshd_admin_net" => "0.0.0.0/0",
        "ssh_allow_groups" => "vagrant"
      }
    end
  end
end
