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
grep -vE '^#|^$' /tmp/suid.list | while read -r suid; do
  file=$(command -v "$suid")
  sfile=$(sudo which "$suid")
  if [ -x "$file" ]; then
    echo "  - $file" >> "suid.list"
  fi
  if [ -x "$sfile" ]; then
    echo "  - $sfile" >> "suid.list"
  fi
done

grep -vE '^#|^$' /etc/shells | while read -r S; do
  echo "  - $S" >> "suid.list"
done

cd ~ || exit 1

sudo "$PKG" -y install git

git clone https://github.com/CISOFy/lynis
git clone https://github.com/konstruktoid/hardening.git

sudo "$PKG" -y remove git

if lsb_release -a 2>/dev/null | grep -qi ubuntu; then
  echo "Running bats tests."
  sudo "$PKG" -y install bats
  cd ~/hardening/tests || exit 1
  PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin sudo bats . | tee  ~/bats.log
  sudo chown vagrant:vagrant ~/bats.log
else
  echo "not ok: not ubuntu" > ~/bats.log
fi

echo "Running Lynis."
cd ~ || exit 1
sudo chown -R root:root lynis
sudo chmod a+rx lynis
cd lynis || exit 1

LANG=C sudo ./lynis audit system
sudo cp '/var/log/lynis-report.dat' ~/
sudo chown vagrant:vagrant ~/lynis-report.dat

echo "ansible_version=$(ansible --version | grep '^ansible')" >> ~/lynis-report.dat
