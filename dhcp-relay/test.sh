#!/bin/bash -x

OUTER_VLAN=83
INNER_VLAN=20
UPLINK_VLAN=84
IF="ens6f0"

DHCP_SERVER="185.107.12.59"
IPADDR_BNG="194.45.77.57"
IPADDR_UPLINK="185.107.12.99"
UPLINK_GW="185.107.12.97"
CLIENT_IP="194.45.77.59"

echo "Setting up VLAN interfaces"
ethtool -K $IF txvlan off
ethtool -K $IF rxvlan off
# Increase MTU to allow second VLAN tag (QinQ)
ip link set dev $IF mtu 1504
ip link set dev $IF up
# Set outer VLAN interface
ip link add link $IF name $IF.$OUTER_VLAN type vlan id $OUTER_VLAN
ip link set $IF.$OUTER_VLAN up

CLIENT_IF=$IF.$OUTER_VLAN.$INNER_VLAN

# Set inner VLAN interface
ip link add link $IF.$OUTER_VLAN name $CLIENT_IF type vlan id $INNER_VLAN
ip link set $CLIENT_IF up

# Set accept_local for VLAN interface
echo 1 > /proc/sys/net/ipv4/conf/$CLIENT_IF/accept_local

# Disable reverse path filtering for VLAN interface
echo 0 > /proc/sys/net/ipv4/conf/$CLIENT_IF/rp_filter

# Enable ARP proxy for VLAN interface
echo 1 > /proc/sys/net/ipv4/conf/$CLIENT_IF/proxy_arp

# Insert /32 route to client
ip route add $CLIENT_IP/32 dev $CLIENT_IF

# Set IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Set L3 config for BNG interface
ip addr add $IPADDR_BNG/29 dev lo

# Create upstream interface
ip link add link $IF name $IF.$UPLINK_VLAN type vlan id $UPLINK_VLAN
ip link set dev $IF.$UPLINK_VLAN
ip link set $IF.$UPLINK_VLAN up

# Disable RP filtering globally to receive DHCP requests through unnumbered
# interface
echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter

# Set L3 config for upstream interface
ip addr add $IPADDR_UPLINK/28 dev $IF.$UPLINK_VLAN
ip route replace default via $UPLINK_GW

echo "Compiling XDP program"
make

echo "Launching XDP program"
./dhcp_user_xdp -i $IF -d $DHCP_SERVER -s $IPADDR_UPLINK