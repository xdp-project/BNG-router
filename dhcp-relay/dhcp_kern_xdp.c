/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <net/if.h>    /* IF_NAMESIZE */
#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <xdp/parsing_helpers.h>
#include <xdp/context_helpers.h>
#include "dhcp-relay.h"

#define bpf_printk(fmt, ...)                                    \
({                                                              \
        char ____fmt[] = fmt;                                   \
        bpf_trace_printk(____fmt, sizeof(____fmt),              \
                         ##__VA_ARGS__);                        \
})

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

//static int memcpy_var(void *to, void *from, __u8 len) {
//	__u8 *t8 = to, *f8 = from;
//	int i;
//
//	if (len > RAI_OPTION_LEN) {
//		return -1;
//	}
//
//	for (i = 0; i < len; i++) {
//
//		if (i > RAI_OPTION_LEN) {
//			return -1;
//		}
//
//		*t8++ = *f8++;
//
//	}
//
//
//	if (i == RAI_OPTION_LEN)
//		return -1;
//
//	return 0;
//
//}

int u16_to_ascii(struct sub_option *opt, __u8 offset, __u16 num) {

	if (opt == NULL)
		return -1;

	if (offset > RAI_OPTION_LEN)
		return -1;

	if (offset < U16_ASCII_LEN)
		return -1;

	__u8 i;
	//#pragma unroll U16_ASCII_LEN
	for (i = offset - 1; i > 0; i--) {

		if (i == 0)
			break;

		opt->val[i] = (__u8) (num % 10) + '0';
		num /= 10;
		if (num == 0)
			break;

	}

	if (i > 0) {
		opt->val[--i] = '.';
	}

	if (i > RAI_OPTION_LEN)
		return -1;

	return i;

}

int str_len(struct dev_name *dev) {

	if (dev == NULL)
		return -1;

	__u8 i = 0;
	for (i = 0; i < RAI_OPTION_LEN; i++)
		if (dev->name[i] == 0)
			break;

	return i;

}

int copy_dev_name(struct sub_option *dest, __u8 offset, struct dev_name *dev) {

	if (dest == NULL)
		return -1;

	if (dev == NULL)
		return -1;

	__u8 i;

	/* Copy device name and left-align VLAN part*/
#pragma unroll RAI_OPTION_LEN
	for (i = 0; i < RAI_OPTION_LEN; i++) {

		if (i < dev->len) {
			/* Copy device name */
			dest->val[i] = dev->name[i];
		} else if (offset < RAI_OPTION_LEN) {
			/* Move VLAN part (all bytes from offset and up) */
			dest->val[i] = dest->val[offset];
			dest->val[offset++] = 0;
		}

	}

	return offset;
}

/* Inserts DHCP option 82 into the received DHCP packet
 * at the specified offset.
 */
static __always_inline int write_dhcp_option_82(void *ctx, int offset,
		struct collect_vlans *vlans, struct dev_name dev) {

	struct dhcp_option_82 option = {0};

	option.t = DHO_DHCP_AGENT_OPTIONS;
	option.len = sizeof (struct sub_option) + sizeof (struct sub_option);
	option.circuit_id.option_id = RAI_CIRCUIT_ID;
	option.circuit_id.len = sizeof (option.circuit_id.val);
	option.remote_id.option_id = RAI_REMOTE_ID;
	option.remote_id.len = sizeof (option.remote_id.val);

	/* Reconstruct VLAN device name
	 * Convert VLAN tags to ASCII from right to left, starting with
	 * inner VLAN tag.
	 * Device name is up to 16 characters long - remaining buffer space
	 * contains null bytes.
	 */

	int i = RAI_OPTION_LEN;

	__u16 inner_vlan = vlans->id[1];
	__u16 outer_vlan = vlans->id[0];

	if (inner_vlan != 0) {

		/* Convert inner VLAN to ASCII */
		i = u16_to_ascii(&option.circuit_id, RAI_OPTION_LEN, inner_vlan);
		if (i < 0) {
			return -1;
		}

	}

	if (outer_vlan != 0) {

		/* Convert outer VLAN to ASCII */
		i = u16_to_ascii(&option.circuit_id, i, outer_vlan);
		if (i < 0) {
			return -1;
		}

	}

	/* Insert device name and left-align circuit ID */
	i = copy_dev_name(&option.circuit_id, i, &dev);
	if (i < 0)
		return -1;

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

/* Delta value for tail adjustment */
#define delta sizeof(struct dhcp_option_82)

#ifndef DHCP_MAX_OPTIONS
#define DHCP_MAX_OPTIONS 20
#endif

/* buf needs to be a static global var because the verifier won't allow
 * unaligned stack accesses
 */
//static __u8 buf[static_offset + VLAN_MAX_DEPTH * sizeof (struct vlan_hdr)];

/* XDP program for parsing the DHCP packet and inserting the option 82*/
SEC(XDP_PROG_SEC)
int xdp_dhcp_relay(struct xdp_md *ctx) {

	/* Tail extend packet */
	int res = bpf_xdp_adjust_tail(ctx, delta);
	if (res != 0) {
		bpf_printk("Cannot tail extend packet, delta %i - error code %i", delta, res);
		return XDP_PASS;
	}

	//bpf_printk("Tail extended packet by %i bytes", delta);

	void *data_end = (void *) (long) ctx->data_end;
	void *data = (void *) (long) ctx->data;
	struct collect_vlans vlans = {0};
	struct ethhdr *eth;
	struct iphdr *ip;
	struct iphdr oldip;
	struct udphdr *udp;
	struct dhcp_packet *dhcp;
	struct dev_name dev = {0};
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
	char *dev_config;
	__u8 i = 0;
	__u8 head_adjusted = 0;

	/* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	int ether_type;
	int h_proto = 0;
	int key = 0;
	int len = 0;

	if (data + 1 > data_end) {
		goto out;
	}

	nh.pos = data;
	ether_type = parse_ethhdr_vlan(&nh, data_end, &eth, &vlans);
	/* Check for valid EtherType */
	if (ether_type < 0) {
		bpf_printk("Cannot determine EtherType");
		goto out;
	}

	if (ether_type != bpf_htons(ETH_P_IP)) {
		//bpf_printk("Ethertype %x is not ETH_P_IP", bpf_ntohs(ether_type));
		goto out;
	}

	/* Check at least one vlan tag is present */
	if (vlans.id[0] == 0) {
		bpf_printk("No outer VLAN tag set");
		goto out;
	}

	if (vlans.id[1] == 0) {
		bpf_printk("No inner VLAN tag set");
	}

	h_proto = parse_iphdr(&nh, data_end, &ip);

	/* Only handle fixed-size IP header due to static copy */
	if (h_proto != IPPROTO_UDP || ip->ihl > 5) {
		bpf_printk("Not UDP");
		goto out;
	}

	/* Old ip hdr backup for re-calculating the checksum later */
	oldip = *ip;
	ip_offset = ((void *) ip - data) & 0x3fff;
	len = parse_udphdr(&nh, data_end, &udp);
	if (len < 0)
		goto out;

	/* Handle DHCP packets only */
	if (udp->dest != bpf_htons(DHCP_SERVER_PORT) && udp->dest != bpf_htons(DHCP_CLIENT_PORT)) {
		bpf_printk("Not DHCP");
		goto out;
	}

	/* Increase IP length header */
	ip->tot_len += bpf_htons(delta);

	/* Increase UDP length header */
	udp->len += bpf_htons(delta);

	udp->check = 0;

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
	dev_config = bpf_map_lookup_elem(&device_name, &key);
	if (dev_config == NULL)
		goto out;

	memcpy(dev.name, dev_config, RAI_OPTION_LEN);
	dev.len = str_len(&dev);

	/* Increment offset by 4 bytes for each VLAN (to accomodate VLAN headers */
#pragma unroll VLAN_MAX_DEPTH
	for (i = 0; i < VLAN_MAX_DEPTH; i++) {
		if (vlans.id[i]) {

			bpf_printk("Found VLAN tag %i at depth %i", vlans.id[i], i);

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

	/* Check hops */
	if (dhcp->hops > 16) {
		bpf_printk("Max hops exceeded, discarding packet");
		rc = XDP_ABORTED;
		goto out;
	}

	/* Increment hops */
	dhcp->hops++;

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

		/* Set destination MAC */
		memcpy(eth->h_dest, relay_hwaddr, ETH_ALEN);

		// Set source MAC
		//memcpy(eth->h_source, relay_hwaddr, ETH_ALEN);

		/* Set GIADDR */
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

		struct collect_vlans *new_vlans;
		new_vlans = bpf_map_lookup_elem(&client_vlans, &client_mac);
		if (new_vlans == NULL) {
			bpf_printk("Could not find map entry for MAC %i", client_mac);
			goto out;
		}

		bpf_printk("Found map entry for MAC %x", client_mac);

		/* Set destination MAC */
		memcpy(eth->h_dest, dhcp->chaddr, ETH_ALEN);

		/* Set source MAC */
		memcpy(eth->h_source, relay_hwaddr, ETH_ALEN);

		/* Set destination IP */
		ip->daddr = IP_ADDR_BCAST;

		/* Set source IP */
		ip->saddr = *relay_agent_ip;

		/* Add / replace VLAN tags */
		if (vlans.id[0] != 0) {
			bpf_printk("Outer VLAN %i found, will change to %i", vlans.id[0], new_vlans->id[0]);

			struct vlan_hdr *outer_vlh = data + ETH_HLEN;
			outer_vlh->h_vlan_TCI = bpf_htons((bpf_ntohs(outer_vlh->h_vlan_TCI) & 0xf000) | new_vlans->id[0]);

		}

		if (vlans.id[1] != 0) {
			bpf_printk("Inner VLAN %i found, will change to %i", vlans.id[1], new_vlans->id[1]);

			struct vlan_hdr *inner_vlh = data + ETH_HLEN + sizeof (struct vlan_hdr);
			inner_vlh->h_vlan_TCI = bpf_htons((bpf_ntohs(inner_vlh->h_vlan_TCI) & 0xf000) | new_vlans->id[1]);

		} else {
			bpf_printk("Inner VLAN not found, will insert %i", new_vlans->id[1]);

			/* Adjust header by -4 bytes to make space for VLAN header */
			if (bpf_xdp_adjust_head(ctx, -(int) sizeof (struct vlan_hdr))) {
				bpf_printk("Cannot head-adjust packet by %i bytes, aborting", -(int) sizeof (struct vlan_hdr));
				rc = XDP_ABORTED;
				goto out;
			}

			bpf_printk("Head-adjusted packet by %i bytes", -(int) sizeof (struct vlan_hdr));

			head_adjusted = 1;

			data_end = (void *) (long) ctx->data_end;
			data = (void *) (long) ctx->data;

			/* Verifier check */
			if (data + ETH_ALEN + ETH_ALEN + sizeof (struct vlan_hdr) + sizeof (struct vlan_hdr) > data_end) {
				rc = XDP_ABORTED;
				goto out;
			}

			/* Move MAC address headers + outer VLAN tag to beginning of packet */
			memmove(data, data + sizeof (struct vlan_hdr), ETH_ALEN + ETH_ALEN + sizeof (struct vlan_hdr));

			bpf_printk("Moved %i bytes from offset %i to offset %i", ETH_ALEN + ETH_ALEN + sizeof (struct vlan_hdr), sizeof (struct vlan_hdr), 0);

			/* Make new inner VLAN header (copy from outer VLAN header) */
			memcpy(data + ETH_ALEN + ETH_ALEN + sizeof (struct vlan_hdr), data + ETH_ALEN + ETH_ALEN, sizeof (struct vlan_hdr));

			bpf_printk("Copied %i bytes from offset %i to offset %i", sizeof (struct vlan_hdr), ETH_ALEN + ETH_ALEN, ETH_ALEN + ETH_ALEN + sizeof (struct vlan_hdr));

			bpf_printk("Will modify VLAN header at offset %i", ETH_ALEN + ETH_ALEN + sizeof (struct vlan_hdr));

			struct vlan_hdr *vlh = data + ETH_ALEN + ETH_ALEN + sizeof (struct vlan_hdr) + 2;
			vlh->h_vlan_TCI = bpf_htons((bpf_ntohs(vlh->h_vlan_TCI) & 0xf000) | new_vlans->id[1]);

			offset += sizeof (struct vlan_hdr);
			vlan_length += sizeof (struct vlan_hdr);

			/* Parse DHCP packet */
			if (data + vlan_length + dhcp_offset + sizeof (dhcp) > data_end) {
				goto out;
			}
			dhcp = data + vlan_length + dhcp_offset;

			bpf_printk("Inserted VLAN header");

		}

		rc = XDP_TX;

	}

	/* Check if we exceed boundaries to make verifier happy */
	if (data + offset > data_end)
		goto out;

	option_offset = offset;

	__u8 n = 0;

	__u8 *pos = (__u8 *) (data + option_offset);

	/* Loop through all DHCP options */
	//#pragma unroll DHCP_MAX_OPTIONS
	for (i = 0; i < DHCP_MAX_OPTIONS; i++) {

		/* Verifier check */
		if (pos + 1 > data_end)
			break;

		/* Read option code */
		option_code = *pos;

		bpf_printk("Got option code %i at offset %i, hex %x", option_code, option_offset, option_offset);

		if (option_code == 82 && dhcp->op == DHCP_REPLY) {

			bpf_printk("Will erase DHCP option 82");

			/* Set new option 255 */
			*pos = 255;

			/* Increment pointer 2nd byte of option 82 */
			pos++;

			/* Verifier check */
			if (pos + 1 > data_end)
				break;

			/* Erase remainder of option 82 */
			for (n = 0; n < sizeof (struct dhcp_option_82); n++) {

				if (pos + 1 > data_end)
					break;

				*pos++ = 0;

			}

			break;

		}

		if (option_code == 255) {

			bpf_printk("Going to write DHCP option 82 at offset %i", option_offset);

			/* Insert Option 82 before END option */
			if (write_dhcp_option_82(ctx, option_offset, &vlans, dev)) {
				bpf_printk("Could not write DHCP option 82 at offset %i", option_offset);
				//return XDP_ABORTED;
				break;
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
				//return XDP_ABORTED;
				break;
			}

			bpf_printk("Wrote DHCP option 255 at offset %i, returning XDP_PASS", option_offset);

			break;
		}

		pos++;

		/* Verifier check */
		if (pos + 1 > data_end) {
			break;
		}

		option_length = *pos;
		option_offset += option_length + 2;

		/* Verifier check */
		if (pos + 1 > data_end) {
			break;
		}
		pos++;

		/* Verifier check */
		if (pos + option_length > data_end) {
			break;
		}

		/* Skip option value (go to next option) */
		pos += option_length;

	}

	/* Adjust IP offset for VLAN header when VLAN header has been added */
	if (head_adjusted) {
		ip = data + ip_offset + sizeof (struct vlan_hdr);
	} else {
		ip = data + ip_offset;
	}
	if (ip + 1 > data_end) {
		return XDP_ABORTED;
	}

	/* Overwrite the destination IP in IP header */
	ip->daddr = *dhcp_srv_ip;

	/* Overwrite source IP */
	ip->saddr = *relay_agent_ip;

	/* Re-calculate ip checksum */
	__u32 sum = calc_ip_csum(&oldip, ip, oldip.check);
	ip->check = ~sum;

	goto out;

out:
	return rc;
}

char _license[] SEC("license") = "GPL";