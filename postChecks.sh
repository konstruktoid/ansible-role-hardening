#!/bin/sh
if command -v apt-get; then
  PKG="apt-get"
elif command -v dnf; then
  PKG="dnf"
elif command -v yum; then
  PKG="yum"
else
  exit 1
fi

if lsb_release -a 2>/dev/null | grep -qi debian; then
  if grep -qiRE '^deb.*redir' /etc/apt/*; then
echo "deb http://ftp.debian.org/debian buster main
deb http://ftp.debian.org/debian buster-updates main
deb http://security.debian.org/debian-security buster/updates main
deb-src http://ftp.debian.org/debian buster main
deb-src http://ftp.debian.org/debian buster-updates main
deb-src http://security.debian.org/debian-security buster/updates main" | sudo tee /etc/apt/sources.list
  fi

  sudo "$PKG" -y update
fi

cd ~ || exit 1

echo "Generating SUID list."
curl -sSL 'https://raw.githubusercontent.com/konstruktoid/hardening/master/misc/suid.list' > /tmp/suid.list
grep -E '^[a-zA-Z0-9]' /tmp/suid.list | while read -r suid; do
  file=$(command -v "$suid")
  if [ -x "$file" ]; then
    echo "  - $file" >> "suid.list"
  fi
done

grep -vE '^#|^$' /etc/shells | while read -r S; do
  echo "  - $S" >> "suid.list"
done

echo "Running Lynis."
sudo "$PKG" -y install git

git clone https://github.com/CISOFy/lynis

sudo chown -R root:root lynis
sudo chmod a+rx lynis
cd lynis || exit 1

LANG=C sudo ./lynis audit system
sudo cp '/var/log/lynis-report.dat' ~/
sudo chown vagrant:vagrant ~/lynis-report.dat
echo "ansible_version=$(ansible --version | grep '^ansible')" >> ~/lynis-report.dat
