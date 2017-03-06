# -*- mode: ruby -*-
# vi: set ft=ruby :

# Vagrantfile API/syntax version. Don't touch unless you know what you're doing!
VAGRANTFILE_API_VERSION = "2"
Vagrant.require_version ">=1.7.0"

$bootstrap_fedora = <<SCRIPT
dnf -y update
dnf -y install autoconf automake openssl-devel libtool \
               python-devel python3-devel \
               python-twisted python-zope-interface \
               desktop-file-utils groff graphviz rpmdevtools nc curl \
               wget python-six pyftpdlib checkpolicy selinux-policy-devel \
               libcap-ng-devel kernel-devel-`uname -r` ethtool python-tftpy
echo "search extra update built-in" >/etc/depmod.d/search_path.conf
SCRIPT

$bootstrap_debian = <<SCRIPT
aptitude -y update
aptitude -y upgrade
aptitude -y install -R \
		build-essential dpkg-dev lintian devscripts fakeroot \
		debhelper dh-autoreconf uuid-runtime \
		autoconf automake libtool \
		python-all python-twisted-core python-twisted-conch \
		xdg-utils groff graphviz netcat curl \
		wget python-six ethtool \
		libcap-ng-dev libssl-dev python-dev openssl \
		python-pyftpdlib python-flake8 python-tftpy \
		linux-headers-`uname -r`
SCRIPT

$bootstrap_centos = <<SCRIPT
yum -y update
yum -y install autoconf automake openssl-devel libtool \
               python-twisted-core python-zope-interface \
               desktop-file-utils groff graphviz rpmdevtools nc curl \
               wget python-six pyftpdlib checkpolicy selinux-policy-devel \
               libcap-ng-devel kernel-devel-`uname -r` ethtool net-tools
SCRIPT

$configure_ovs = <<SCRIPT
cd /vagrant
./boot.sh
[ -f Makefile ] && ./configure && make distclean
mkdir -p ~/build
cd ~/build
/vagrant/configure --with-linux=/lib/modules/`uname -r`/build --enable-silent-rules
SCRIPT

$build_ovs = <<SCRIPT
cd ~/build
make
SCRIPT

$test_kmod = <<SCRIPT
cd ~/build
make check-kmod RECHECK=yes
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
rpm -ivh $HOME/rpmbuild/RPMS/x86_64/openvswitch-$PACKAGE_VERSION-1.fc23.x86_64.rpm
systemctl enable openvswitch
systemctl start openvswitch
systemctl status openvswitch
SCRIPT

$install_centos_rpm = <<SCRIPT
cd ~/build
PACKAGE_VERSION=`autom4te -l Autoconf -t 'AC_INIT:$2' /vagrant/configure.ac`
make && make dist
rpmdev-setuptree
cp openvswitch-$PACKAGE_VERSION.tar.gz $HOME/rpmbuild/SOURCES
rpmbuild --bb -D "kversion `uname -r`" /vagrant/rhel/openvswitch-kmod-fedora.spec
rpmbuild --bb --without check /vagrant/rhel/openvswitch-fedora.spec
rpm -e openvswitch
rpm -ivh $HOME/rpmbuild/RPMS/x86_64/openvswitch-$PACKAGE_VERSION-1.x86_64.rpm
systemctl enable openvswitch
systemctl start openvswitch
systemctl status openvswitch
SCRIPT

$install_deb = <<SCRIPT
cd ~/build
PACKAGE_VERSION=`autom4te -l Autoconf -t 'AC_INIT:$2' /vagrant/configure.ac`
make dist
cd ~/
ln -sf ~/build/openvswitch-$PACKAGE_VERSION.tar.gz openvswitch_$PACKAGE_VERSION.orig.tar.gz
rm -rf ~/openvswitch-$PACKAGE_VERSION
tar xzf openvswitch_$PACKAGE_VERSION.orig.tar.gz
cd ~/openvswitch-$PACKAGE_VERSION
debuild -us -uc
dpkg -i ../openvswitch-{common,switch}*deb
systemctl enable openvswitch-switch
systemctl start openvswitch-switch
systemctl status openvswitch-switch
SCRIPT

$test_ovs_system_userspace = <<SCRIPT
cd ~/build
make check-system-userspace RECHECK=yes
SCRIPT

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|
  config.vm.define "debian-8" do |debian|
       debian.vm.box = "debian/jessie64"
       debian.vm.synced_folder ".", "/vagrant", type: "rsync"
       debian.vm.provision "bootstrap", type: "shell", inline: $bootstrap_debian
       debian.vm.provision "configure_ovs", type: "shell", inline: $configure_ovs
       debian.vm.provision "build_ovs", type: "shell", inline: $build_ovs
       debian.vm.provision "test_ovs_kmod", type: "shell", inline: $test_kmod
       debian.vm.provision "test_ovs_system_userspace", type: "shell", inline: $test_ovs_system_userspace
       debian.vm.provision "install_deb", type: "shell", inline: $install_deb
  end
  config.vm.define "fedora-23" do |fedora|
       fedora.vm.box = "fedora/23-cloud-base"
       fedora.vm.synced_folder ".", "/vagrant", type: "rsync"
       fedora.vm.provision "bootstrap", type: "shell", inline: $bootstrap_fedora
       fedora.vm.provision "configure_ovs", type: "shell", inline: $configure_ovs
       fedora.vm.provision "build_ovs", type: "shell", inline: $build_ovs
       fedora.vm.provision "test_ovs_kmod", type: "shell", inline: $test_kmod
       fedora.vm.provision "test_ovs_system_userspace", type: "shell", inline: $test_ovs_system_userspace
       fedora.vm.provision "install_rpm", type: "shell", inline: $install_rpm
  end
  config.vm.define "centos-7" do |centos|
       centos.vm.box = "centos/7"
       centos.vm.synced_folder ".", "/vagrant", type: "rsync"
       centos.vm.provision "bootstrap", type: "shell", inline: $bootstrap_centos
       centos.vm.provision "configure_ovs", type: "shell", inline: $configure_ovs
       centos.vm.provision "build_ovs", type: "shell", inline: $build_ovs
       centos.vm.provision "test_ovs_kmod", type: "shell", inline: $test_kmod
       centos.vm.provision "test_ovs_system_userspace", type: "shell", inline: $test_ovs_system_userspace
       centos.vm.provision "install_rpm", type: "shell", inline: $install_centos_rpm
  end
end
