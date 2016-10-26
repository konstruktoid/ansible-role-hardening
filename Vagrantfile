Vagrant.configure("2") do |ubuxen|
  ubuxen.vm.box = "ubuntu/xenial64"

  ubuxen.vm.provider "virtualbox" do |vb|
    vb.memory = "2048"
    vb.name = "ubuxen"
  end

  ubuxen.vm.network "private_network", ip:"10.2.3.41"
  ubuxen.vm.hostname = "ubuxen"
  ubuxen.vm.provision "shell",
    inline: "apt-get update && apt-get -y install ansible aptitude python --no-install-recommends"
  ubuxen.vm.provision "ansible" do |p|
    p.verbose = "v"
    p.limit = "all"
    p.playbook = "hardening-test.yml"
    p.extra_vars = {
      "sshd_admin_net" => "0.0.0.0/0"
    }
  end
end
