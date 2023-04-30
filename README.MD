# Debian setup
sudo nano /etc/sysctl.conf

net.ipv4.icmp_echo_ignore_all = 1

net.ipv4.conf.all.accept_redirects = 0

sudo sysctl -p
