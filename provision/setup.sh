#!/bin/sh
apt-get update
apt-get -y install aptitude dnsmasq python python-pexpect software-properties-common --no-install-recommends
apt-add-repository --yes --update ppa:ansible/ansible
apt-get -y install ansible --no-install-recommends
