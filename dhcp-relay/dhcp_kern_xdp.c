/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <linux/bpf.h>
#include <linux/in.h>
#include <net/if.h>				/* IF_NAMESIZE */
#include <bpf/bpf_helpers.h>
#include <xdp/parsing_helpers.h>
#include <xdp/context_helpers.h>
#include "dhcp-relay.h"

/*
 * This map is for storing the DHCP relay configuration, including:
 * 
 * Relay server IP address
 * Relay agent IP address
 * Relay agent MAC address
 * 
 * Configuration parameters are set by CLI arguments in user space program.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 3);
} relay_config SEC(".maps");

/*
 * This map is for storing the device name in clear text.
 * Device name is used for DHCP option 82.
 */

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, char[IF_NAMESIZE]);
	__uint(max_entries, 1);
} device_name SEC(".maps");

/*
 * This map is used for storing client requests along with their matching
 * VLAN tags. That way, we can handle DHCP server replies.
 * Client MAC address is used as key, VLAN headers as value.
 */

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u64);
	__type(value, struct collect_vlans);
	__uint(max_entries, 16384);
} client_vlans SEC(".maps");

/* Inserts DHCP option 82 into the received dhcp packet
 * at the specified offset.
 */
static __always_inline int write_dhcp_option_82(void *ctx, int offset,
	struct collect_vlans *vlans, char *dev) {
	struct dhcp_option_82 option;

	option.t = DHO_DHCP_AGENT_OPTIONS;
	option.len = sizeof(struct sub_option) + sizeof(struct sub_option);
	option.circuit_id.option_id = RAI_CIRCUIT_ID;
	option.circuit_id.len = IF_NAMESIZE;
	memcpy(option.circuit_id.val, dev, IF_NAMESIZE);
	//option.circuit_id.val = bpf_ntohs(vlans->id[0]);
	option.remote_id.option_id = RAI_REMOTE_ID;
	option.remote_id.len = IF_NAMESIZE;
	//option.remote_id.val = bpf_ntohs(vlans->id[1]);
	
	return xdp_store_bytes(ctx, offset, &option, sizeof (option), 0);
}

/* Inserts DHCP option 255 into the received dhcp packet
 * at the specified offset.
 */
static __always_inline int write_dhcp_option_255(void *ctx, int offset) {
	struct dhcp_option_255 option;

	option.t = 255;

	return xdp_store_bytes(ctx, offset, &option, sizeof (option), 0);
}

/* Calculates the IP checksum */
static __always_inline int calc_ip_csum(struct iphdr *oldip, struct iphdr *ip,
	__u32 oldcsum) {
	__u32 size = sizeof (struct iphdr);
	__u32 csum = bpf_csum_diff((__be32 *) oldip, size, (__be32 *) ip, size,
		~oldcsum);
	__u32 sum = (csum >> 16) + (csum & 0xffff);
	sum += (sum >> 16);
	return sum;
}

#define dhcp_offset                                                            \
	sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr)
//offsetof(struct dhcp_packet, options)

/* Offset to DHCP Options part of the packet */
#define static_offset                                                          \
	sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + \
		offsetof(struct dhcp_packet, options)

/* Delta value to be adjusted at xdp head*/
#define delta sizeof(struct dhcp_option_82)

#ifndef DHCP_MAX_OPTIONS
#define DHCP_MAX_OPTIONS 20
#endif

/* buf needs to be a static global var because the verifier won't allow
 * unaligned stack accesses
 */
//static __u8 buf[static_offset + VLAN_MAX_DEPTH * sizeof (struct vlan_hdr)];

#define bpf_printk(fmt, ...)                                    \
({                                                              \
        char ____fmt[] = fmt;                                   \
        bpf_trace_printk(____fmt, sizeof(____fmt),              \
                         ##__VA_ARGS__);                        \
})

/* XDP program for parsing the DHCP packet and inserting the option 82*/
SEC(XDP_PROG_SEC)
int xdp_dhcp_relay(struct xdp_md *ctx) {

	bpf_printk("\n");

	/* Tail extend packet */
	int res = bpf_xdp_adjust_tail(ctx, delta);
	if (res != 0) {
		bpf_printk("Cannot tail extend packet, delta %i - error code %i", delta, res);
		return XDP_ABORTED;
	}
	
	bpf_printk("Tail extended packet by %i bytes", delta);

	void *data_end = (void *) (long) ctx->data_end;
	void *data = (void *) (long) ctx->data;
	struct collect_vlans vlans = {0};
	struct ethhdr *eth;
	struct iphdr *ip;
	struct iphdr oldip;
	struct udphdr *udp;
	struct dhcp_packet *dhcp;
	__u32 *dhcp_srv_ip;
	__u32 *relay_agent_ip;
	__u64 *relay_hwaddr;
	int rc = XDP_PASS;
	__u16 offset = static_offset;
	__u16 option_offset = offset;
	__u16 ip_offset = 0;
	__u16 vlan_length = 0;
	__u8 option_code = 0;
	__u8 option_length = 0;
	__u64 client_mac = 0;
	char *dev;
	int i = 0;

	/* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	int ether_type;
	int h_proto = 0;
	int key = 0;
	int len = 0;

	if (data + 1 > data_end)
		return XDP_ABORTED;

	nh.pos = data;
	ether_type = parse_ethhdr_vlan(&nh, data_end, &eth, &vlans);
	/* check for valid ether type */
	if (ether_type < 0) {
		bpf_printk("Cannot determine ethertype");
		rc = XDP_ABORTED;
		goto out;
	}
	if (ether_type != bpf_htons(ETH_P_IP)) {
		bpf_printk("Ethertype %#x is not ETH_P_IP", bpf_ntohs(ether_type));
		goto out;
	}

	bpf_printk("Ethertype %x", bpf_ntohs(ether_type));

	/* Check at least two vlan tags are present */
	if (vlans.id[1] == 0) {
		bpf_printk("No VLAN tags set");
		goto out;
	}

	h_proto = parse_iphdr(&nh, data_end, &ip);

	/* Only handle fixed-size IP header due to static copy */
	if (h_proto != IPPROTO_UDP || ip->ihl > 5) {
		goto out;
	}

	/* Old ip hdr backup for re-calculating the checksum later */
	oldip = *ip;
	ip_offset = ((void *) ip - data) & 0x3fff;
	len = parse_udphdr(&nh, data_end, &udp);
	if (len < 0)
		goto out;

	/* Handle DHCP packets only */
	if (udp->dest != bpf_htons(DHCP_SERVER_PORT) && udp->dest != bpf_htons(DHCP_CLIENT_PORT))
		goto out;

	/* Increase IP length header */
	ip->tot_len += bpf_htons(delta);
	
	/* Increase UDP length header */
	udp->len += bpf_htons(delta);
	
	/* Read DHCP server IP from config map */
	key = 0;
	dhcp_srv_ip = bpf_map_lookup_elem(&relay_config, &key);
	if (dhcp_srv_ip == NULL)
		goto out;

	/* Read relay agent IP from config map */
	key = 1;
	relay_agent_ip = bpf_map_lookup_elem(&relay_config, &key);
	if (relay_agent_ip == NULL)
		goto out;

	/* Read relay agent MAC address from config map */
	key = 2;
	relay_hwaddr = bpf_map_lookup_elem(&relay_config, &key);
	if (relay_hwaddr == NULL)
		goto out;
	
	/* Read device name from device map */
	key = 0;
	dev = bpf_map_lookup_elem(&device_name, &key);
	if (dev == NULL)
		goto out;

	/* Copy headers of packet to buf */
	//if (xdp_load_bytes(ctx, 0, buf, static_offset))
	//	goto out;

	/* Increment offset by 4 bytes for each VLAN (to accomodate VLAN headers */
	for (i = 0; i < VLAN_MAX_DEPTH; i++) {
		if (vlans.id[i]) {

			bpf_printk("Found VLAN tag %i at depth %i", vlans.id[i], i);

			/* For each VLAN present, copy 4 bytes of DHCP options to buffer */
			//if (xdp_load_bytes(ctx, offset, buf + offset, 4))
			//	goto out;
			offset += 4;
			vlan_length += 4;
		}
	}

	/* Find packet boundaries */
	data_end = (void *) (long) ctx->data_end;
	data = (void *) (long) ctx->data;

	/* Parse DHCP packet */
	if (data + vlan_length + dhcp_offset + sizeof (dhcp) > data_end) {
		goto out;
	}
	dhcp = data + vlan_length + dhcp_offset;

	/* Store client MAC */
	if (dhcp->chaddr + ETH_ALEN > data_end) {
		goto out;
	}
	memcpy(&client_mac, dhcp->chaddr, ETH_ALEN);

	bpf_printk("Parsing DHCP packet, opcode %i, hops %i", dhcp->op, dhcp->hops);

	if (dhcp->op == DHCP_REQUEST && (eth->h_dest[0] == 0xff
		&& eth->h_dest[1] == 0xff
		&& eth->h_dest[2] == 0xff
		&& eth->h_dest[3] == 0xff
		&& eth->h_dest[4] == 0xff
		&& eth->h_dest[5] == 0xff)) {

		/* Request from client received as broadcast */

		bpf_printk("Broadcast packet received, opcode %i, hops %i", dhcp->op, dhcp->hops);

		// Set destination MAC
		memcpy(eth->h_dest, relay_hwaddr, ETH_ALEN);

		// Set source MAC
		//memcpy(eth->h_source, relay_hwaddr, ETH_ALEN);

		// Set GIADDR
		if (&dhcp->giaddr.s_addr + sizeof (relay_agent_ip) > data_end) {
			rc = XDP_ABORTED;
			goto out;
		}
		dhcp->giaddr.s_addr = *relay_agent_ip;

		/* Save client VLAN in state map */
		if (bpf_map_update_elem(&client_vlans, &client_mac, &vlans, BPF_ANY)) {
			bpf_printk("Could not save DHCP request in state map");
			goto out;
		}


	} else if (dhcp->op == DHCP_REPLY && (eth->h_dest[0] != 0xff
		|| eth->h_dest[1] != 0xff
		|| eth->h_dest[2] != 0xff
		|| eth->h_dest[3] != 0xff
		|| eth->h_dest[4] != 0xff
		|| eth->h_dest[5] != 0xff)) {

		/* Response from server received as unicast */

		bpf_printk("Unicast packet received, opcode %i, hops %i", dhcp->op, dhcp->hops);

		/* FIXME: Add code for reply packets
		 * Basically:
		 * - Set dest and src MAC
		 * - Add VLAN tags
		 * - Remove option 82
		 * - Use XDP_TX (or XDP_REDIRECT) to send the response
		 * to the end user
		 */

		struct collect_vlans *new_vlans;
		new_vlans = bpf_map_lookup_elem(&client_vlans, &client_mac);
		if (new_vlans == NULL) {
			bpf_printk("Could not find map entry for MAC %i", client_mac);
			goto out;
		}

		bpf_printk("Found map entry for MAC %i", client_mac);

	}

	/* Check hops */
	if (dhcp->hops > 16) {
		bpf_printk("Max hops exceeded, discarding packet");
		rc = XDP_ABORTED;
		goto out;
	}

	/* Increment hops */
	dhcp->hops++;

	/* Check if we exceed boundaries to make verifier happy */
	if (data + offset > data_end)
		goto out;

	option_offset = offset;

	__u8 *pos = (__u8 *) (data + option_offset);

	/* Loop through all DHCP options */
#pragma unroll DHCP_MAX_OPTIONS
	for (i = 0; i < DHCP_MAX_OPTIONS; i++) {

		/* Verifier check */
		if (pos + 1 > data_end)
			break;

		option_code = *pos;

		bpf_printk("Got option code %i at offset %i, hex %x", option_code, option_offset, option_offset);

		if (option_code == 255) {

			bpf_printk("Going to write DHCP option at offset %i", option_offset);

			/* Insert Option 82 before END option */
			if (write_dhcp_option_82(ctx, option_offset, &vlans, dev)) {
				bpf_printk("Could not write DHCP option 82 at offset %i", option_offset);
				return XDP_ABORTED;
			}

			/* Set END option */

			/* Verifier check */
			if (pos + delta > data_end) {
				return XDP_ABORTED;
			}
			pos += delta;
			option_offset += delta;

			if (write_dhcp_option_255(ctx, option_offset)) {
				bpf_printk("Could not write DHCP option 255 at offset %i", option_offset);
				return XDP_ABORTED;
			}
			
			bpf_printk("Wrote DHCP option 255 at offset %i, returning XDP_PASS", option_offset);

			break;
		}
		pos++;

		option_length = *pos;
		option_offset += option_length + 2;

		if (pos + 1 > data_end) {
			break;
		}
		pos++;

		if (pos + option_length > data_end) {
			break;
		}
		pos += option_length;

	}

	//return XDP_PASS;

	/* Copy stored headers from buf to context */
	/*if (xdp_store_bytes(ctx, 0, buf, static_offset, 0)) {

		bpf_printk("xdp_store_bytes(ctx, 0, buf, %i) failed", static_offset);
		return XDP_ABORTED;
	}*/


	/* make space for option 82 - copy DHCP options after increasing offset */
	/*if (offset > static_offset) {
		offset = static_offset;
		for (i = 0; i < VLAN_MAX_DEPTH; i++) {
			if (vlans.id[i]) {*/
	/*  */
	/*if (xdp_store_bytes(ctx, offset, buf + offset,
		4, 0))
		return XDP_ABORTED;
	offset += 4;
}
	}
	}*/

	ip = data + ip_offset;
	if (ip + 1 > data_end)
		return XDP_ABORTED;

	/* Overwrite the destination IP in IP header */
	ip->daddr = *dhcp_srv_ip;

	/* Overwrite source IP */
	ip->saddr = *relay_agent_ip;

	/* Re-calculate ip checksum */
	__u32 sum = calc_ip_csum(&oldip, ip, oldip.check);
	ip->check = ~sum;
	rc = XDP_PASS;

	goto out;

out:
	return rc;
}

char _license[] SEC("license") = "GPL";