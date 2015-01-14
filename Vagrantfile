# -*- mode: ruby -*-
# vi: set ft=ruby :

# Vagrantfile API/syntax version. Don't touch unless you know what you're doing!
VAGRANTFILE_API_VERSION = "2"
Vagrant.require_version ">=1.7.0"

$bootstrap_fedora = <<SCRIPT
yum -y update
yum -y install autoconf automake openssl-devel libtool \
               python-twisted-core python-zope-interface PyQt4 \
               desktop-file-utils groff graphviz rpmdevtools \
               kernel-devel-`uname -r`
echo "search extra update built-in" >/etc/depmod.d/search_path.conf
cd /vagrant
./boot.sh
SCRIPT

$configure_ovs = <<SCRIPT
mkdir -p ~/build
cd ~/build
/vagrant/configure --with-linux=/lib/modules/`uname -r`/build
SCRIPT

$build_ovs = <<SCRIPT
cd ~/build
make
SCRIPT

$test_kmod = <<SCRIPT
cd ~/build
make check-kmod
SCRIPT

$install_rpm = <<SCRIPT
cd ~/build
PACKAGE_VERSION=`autom4te -l Autoconf -t 'AC_INIT:$2' /vagrant/configure.ac`
make && make dist
rpmdev-setuptree
cp openvswitch-$PACKAGE_VERSION.tar.gz $HOME/rpmbuild/SOURCES
rpmbuild --bb -D "kversion `uname -r`" /vagrant/rhel/openvswitch-kmod-fedora.spec
rpmbuild --bb --without check /vagrant/rhel/openvswitch-fedora.spec
rpm -e openvswitch
rpm -ivh $HOME/rpmbuild/RPMS/x86_64/openvswitch-$PACKAGE_VERSION-1.fc20.x86_64.rpm
systemctl enable openvswitch
systemctl start openvswitch
systemctl status openvswitch
SCRIPT

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|
  config.vm.define "fedora-20" do |fedora|
       fedora.vm.box = "chef/fedora-20"
       fedora.vm.provision "bootstrap", type: "shell", inline: $bootstrap_fedora
       fedora.vm.provision "configure_ovs", type: "shell", inline: $configure_ovs
       fedora.vm.provision "build_ovs", type: "shell", inline: $build_ovs
       fedora.vm.provision "test_ovs_kmod", type: "shell", inline: $test_kmod
       fedora.vm.provision "install_rpm", type: "shell", inline: $install_rpm
  end
end
