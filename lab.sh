systemctl start httpd
ip netns add n1
ip link add dev vm1 type veth peer name vm2
ip link set vm1 netns n1
ip addr add 192.168.42.1/30 dev vm2
ip netns exec n1 ip addr add 192.168.42.2/30 dev vm1
ip netns exec n1 ip link set vm1 up
ip netns exec n1 ip route add default via 192.168.42.1
ip link set vm2 up
# block transmissions
iptables -I INPUT -i vm2 -j DROP -s 192.168.42.2 -d 10.224.123.2 -m tcp --tcp-flags PSH PSH


ip addr add fd42::1/64 dev vm2
ip netns exec n1 ip addr add fd42::2/64 dev vm1
ip addr add fd40::1/64 dev eth0
ip netns exec n1 ip -6 route add fc00::/7 via fd42::1
ip6tables -I INPUT -i vm2 -j DROP -s fd42::2 -d fd40::1 -m tcp --tcp-flags PSH PSH
