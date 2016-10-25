Vagrant.configure(2) do |config|
  config.vm.box = "ubuntu/xenial64"

  config.vm.provider "virtualbox" do |vb|
    vb.memory = "2048"
  end

  (1..3).each do |i|
    config.vm.define "node#{i}" do |node|
    config.vm.network "private_network", ip:"10.2.3.4#{i}"
    config.vm.hostname = "node#{i}"
    config.vm.provision "shell",
      inline: "apt-get update && apt-get -y install ansible aptitude python --no-install-recommends"
    node.vm.provision "ansible" do |p|
      p.playbook = "hardening-test.yml"
      p.groups = {
        "test" => ["node#{i}"]
      }
      p.extra_vars = {
        "sshd_admin_net" => "0.0.0.0/0"
      }
      end
    end
  end
end
