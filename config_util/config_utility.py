# SPDX-License-Identifier: GPL-2.0-or-later

import yaml
import ipaddress
import pr2modules
from pyroute2 import IPRoute


CONFIG_FILE = "./config.yaml"

with open(CONFIG_FILE) as f:
    config = yaml.load(f, Loader=yaml.SafeLoader)


print(config)

# Create the base interface
ip = IPRoute()

for iface in config["interfaces"]:
    if_name = iface["ifname"]
    print(if_name)
    for customer in iface["customers"]:
        inner_vlan_tag = customer["inner_vlan"]
        outer_vlan_tag = customer["outer_vlan"]
        base_iface = ip.link_lookup(ifname=if_name)[0]
        try:
            ip.link(
                "add",
                ifname=f"{if_name}.{inner_vlan_tag}",
                kind="vlan",
                link=base_iface,
                vlan_id=inner_vlan_tag,
            )
        except pr2modules.netlink.exceptions.NetlinkError:
            pass

        # TODO: Check for existing inner tagged iface
        # TODO: Check if the base iface exists
        outer_vlan_iface = f"{if_name}.{inner_vlan_tag}.{outer_vlan_tag}"
        ip.link(
            "add",
            ifname=outer_vlan_iface,
            kind="vlan",
            link=ip.link_lookup(ifname=f"{if_name}.{inner_vlan_tag}")[0],
            vlan_id=outer_vlan_tag,
        )
        # TODO: Check for existing outer tagged iface
        for ip_addr_str in customer["ip_addresses"]:
            ip_addr = ipaddress.ip_interface(ip_addr_str)
            if ip_addr.version == 4:
                mask = ip_addr.network.prefixlen
                ip_str = ip_addr.ip.compressed

                ip.addr(
                    "add",
                    index=ip.link_lookup(outer_vlan_iface)[0],
                    address=ip_str,
                    mask=mask,
                )
# TODO: Handle ipv6
# TODO: Existing addresses


# TODO: Routing (with vlan interface), Attaching ebpf program
