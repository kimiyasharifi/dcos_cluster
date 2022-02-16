# Install vagrant-disksize to allow resizing the vagrant box disk.
unless Vagrant.has_plugin?("vagrant-disksize")
    raise  Vagrant::Errors::VagrantError.new, "vagrant-disksize plugin is missing. Please install it using 'vagrant plugin install vagrant-disksize' and rerun 'vagrant up'"
end



IMAGE_NAME = "ogrange/centos-7.1"
N = 2
VAGRANT_EXPERIMENTAL="disks"

# Configure Shecan Proxy
$setdns = <<-SCRIPT
useradd -m -s /bin/bash -U sakku
echo 'sakku:qazwsx' | chpasswd
echo 'sakku ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/sakku
set -e
cat <<EOF | tee /etc/systemd/resolved.conf
[Resolve]
DNS=178.22.122.100 185.51.200.2
EOF
service systemd-resolved restart
SCRIPT



Vagrant.configure("2") do |config|
  #config.vm.disk :disk, size: "40GB", primary: true
  #config.vm.disk :disk, size: "5GB", name: "extra_storage"
  #config.vm.provider "virtualbox" do |v|
  #  v.memory = 2048
  #  v.cpus = 1
    #config.disksize.size = '5GB'
  #end

  config.vm.define "master-1" do |master|
      master.vm.box = IMAGE_NAME
      master.disksize.size = '50GB'
      master.vm.disk :disk, size: "30GB", primary: true
      master.vm.disk :disk, size: "10GB", name: "extra_storage"
      master.vm.network "private_network", ip: "192.168.50.20"
      master.vm.network "forwarded_port", guest: 80, host: 8081
      master.vm.hostname = "master-1"
  end

  config.vm.define "bootstrap" do |bootstrap|
      bootstrap.vm.box = IMAGE_NAME
      bootstrap.disksize.size = '50GB'
      bootstrap.vm.network "private_network", ip: "192.168.50.21"
      bootstrap.vm.network "forwarded_port", guest: 8080, host: 8080
      bootstrap.vm.hostname = "bootstrap"
  end

  (1..N).each do |i|
    config.vm.define "agent-#{i}" do |agent|
        agent.vm.box = IMAGE_NAME
        agent.disksize.size = '50GB'
        #agent.vm.disk :disk, size: "30GB", primary: true
        #agent.vm.disk :disk, size: "10GB", name: "extra_storage"
        agent.vm.network "private_network", ip: "192.168.50.#{i + 21}"
        agent.vm.hostname = "agent-#{i}"

    end
  end

end
