Vagrant.configure(2) do |cfgubu|
  cfgubu.vm.box = "ubuntu/xenial64"

  cfgubu.vm.provider "virtualbox" do |vb|
    vb.memory = "2048"
  end

  (1..3).each do |i|
    cfgubu.vm.define "ubu#{i}" do |ubu|
    cfgubu.vm.network "private_network", ip:"10.2.3.4#{i}"
    cfgubu.vm.hostname = "ubu#{i}"
    cfgubu.vm.provision "shell",
      inline: "apt-get update && apt-get -y install ansible aptitude python --no-install-recommends"
    ubu.vm.provision "ansible" do |p|
      p.playbook = "hardening-test.yml"
      p.groups = {
        "test" => ["ubu#{i}"]
      }
      p.extra_vars = {
        "sshd_admin_net" => "0.0.0.0/0"
      }
      end
    end
  end
end
