#!/bin/bash
# -x

OUTER_VLAN=83
INNER_VLAN=20
UPLINK_VLAN=84
IF="ens6f0"

DHCP_SERVER="185.107.12.59"
IPADDR_BNG="194.45.77.57"
IPADDR_UPLINK="185.107.12.99"
CLIENT_IP="194.45.77.59"

echo "Unloading XDP program"
./dhcp_user_xdp -i $IF -d $DHCP_SERVER -s $IPADDR_BNG -u

echo "Deleting VLAN interfaces"
# Delete inner VLAN interface
ip link del $IF.$OUTER_VLAN.$INNER_VLAN
# Delete outer VLAN interface
ip link del $IF.$OUTER_VLAN

echo "Deleting uplink interface"
ip link del $IF.$UPLINK_VLAN

# Remove BNG address from loopback interface
ip addr del $IPADDR_BNG/29 dev lo