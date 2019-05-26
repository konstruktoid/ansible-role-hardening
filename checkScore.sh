#!/bin/sh
if command -v apt-get; then
  PKG="apt-get"
elif command -v yum; then
  PKG="yum"
else
  exit 1
fi

if grep -iRE '^deb.*redir' /etc/apt/*; then
echo "deb http://ftp.debian.org/debian stretch main
deb http://ftp.debian.org/debian stretch-updates main
deb http://security.debian.org/debian-security stretch/updates main
deb-src http://ftp.debian.org/debian stretch main
deb-src http://ftp.debian.org/debian stretch-updates main
deb-src http://security.debian.org/debian-security stretch/updates main" | sudo tee /etc/apt/sources.list
fi

cd ~ || exit 1

sudo "$PKG" -y update
sudo "$PKG" -y install git

git clone https://github.com/CISOFy/lynis

sudo chown -R root:root lynis
sudo chmod a+rx lynis
cd lynis || exit 1

LANG=C sudo ./lynis audit system
sudo cp '/var/log/lynis-report.dat' ~/
sudo chown vagrant:vagrant ~/lynis-report.dat
echo "ansible_version=$(ansible --version | grep '^ansible')" >> ~/lynis-report.dat
