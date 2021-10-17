/* SPDX-License-Identifier: GPL-2.0 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */
#include <arpa/inet.h>

#include <sys/ioctl.h>
#include <unistd.h>

#define SERVER_MAP "relay_config"
#define DEVICE_MAP "device_name"
#define XDP_OBJ "dhcp_kern_xdp.o"

static const struct option options[] = {
	{ "help", no_argument, NULL, 'h'},
	{ "interface", required_argument, NULL,
		'i'}, // Name of interface to run on
	{ "dhcp-server", required_argument, NULL, 'd'},
	{ "relay-agent-address", required_argument, NULL, 's'},
	{ "mode", required_argument, NULL, 'm'},
	{ "unload", no_argument, NULL, 'u'},
	{ 0, 0, NULL, 0}
};

static void print_usage(char *argv[]) {
	int i;
	printf("Usage:\n");
	printf("%s\n", argv[0]);
	for (i = 0; options[i].name != 0; i++) {
		printf(" --%-12s", options[i].name);
		if (options[i].flag != NULL)
			printf(" flag (internal value:%d)", *options[i].flag);
		else
			printf(" short-option: -%c", options[i].val);
		printf("\n");
	}
	printf("Example:\n");
	printf("To load program:\n %s -i eth0 -d 10.0.0.1\n", argv[0]);
	printf("To unload program:\n %s -i eth0 -u\n", argv[0]);
	printf("\n");
}

static int xdp_link_detach(int ifindex, __u32 xdp_flags) {
	int err;

	if ((err = bpf_set_link_xdp_fd(ifindex, -1, xdp_flags)) < 0) {
		fprintf(stderr, "ERR: link set xdp unload failed (err=%d):%s\n",
			err, strerror(-err));
		return -1;
	}
	return 0;
}

int xdp_link_attach(int ifindex, __u32 xdp_flags, int prog_fd) {
	int err;

	/* libbpf provide the XDP net_device link-level hook attach helper */
	err = bpf_set_link_xdp_fd(ifindex, prog_fd, xdp_flags);

	if (err < 0) {
		fprintf(stderr,
			"ERR: "
			"ifindex(%d) link set xdp fd failed (%d): %s\n",
			ifindex, -err, strerror(-err));

		switch (-err) {
			case EBUSY:
			case EEXIST:
				fprintf(stderr, "Hint: XDP already loaded on device\n");
				break;
			case EOPNOTSUPP:
				fprintf(stderr, "Hint: Native-XDP not supported\n");
				break;
			default:
				break;
		}
		return -1;
	}

	return 0;
}

/* User program takes two  or three arguments
 * interface name, relay server IP and prog
 * unload flag
 */
int main(int argc, char **argv) {

	char filename[256] = "dhcp_kern_xdp.o";
	int prog_fd, err;
	int opt;

	__u32 xdp_flags = XDP_FLAGS_DRV_MODE;
	char dev[IF_NAMESIZE] = "";
	bool do_unload = 0;
	struct bpf_map *map = NULL;
	struct bpf_map *device_map = NULL;
	struct bpf_object *obj = NULL;
	int map_fd;
	int device_map_fd;
	int key = 0;
	struct in_addr dhcp_server_addr = {};
	struct in_addr relay_agent_addr = {};
	bool dhcp_server_addr_set = false;
	bool relay_agent_addr_set = false;
	__u16 ifindex = 0;
	int fd;
	unsigned char *mac;
	struct ifreq ifr;

	while ((opt = getopt_long(argc, argv, "hui:d:m:s:", options, NULL)) !=
		-1) {
		switch (opt) {
			case 'i':
				strncpy(dev, optarg, IF_NAMESIZE);
				dev[IF_NAMESIZE - 1] = '\0';
				ifindex = if_nametoindex(dev);
				if (ifindex <= 0) {
					printf("Couldn't find ifname:%s \n", dev);
					return -EINVAL;
				}
				break;
			case 'd': // DHCP server address
				if (inet_aton(optarg, &dhcp_server_addr) == 0) {
					fprintf(stderr,
						"Couldn't validate DHCP server IP address:%s\n",
						optarg);
					return -EINVAL;
				}
				dhcp_server_addr_set = true;
				break;
			case 's': // Relay agent address
				if (inet_aton(optarg, &relay_agent_addr) == 0) {
					fprintf(stderr,
						"Couldn't validate relay agent IP address:%s\n",
						optarg);
					return -EINVAL;
				}
				relay_agent_addr_set = true;
				break;
			case 'm':
				if (strcmp(optarg, "skb") == 0) {
					xdp_flags = XDP_FLAGS_SKB_MODE;
				} else if (strcmp(optarg, "drv") != 0) {
					fprintf(stderr, "Invalid mode: %s\n", optarg);
					return -EINVAL;
				}

				break;
			case 'u':
				do_unload = 1;
				break;
			case 'h':
				print_usage(argv);
				exit(0);
			default:
				fprintf(stderr, "Unknown option %s\n", argv[optind]);
				return -EINVAL;
		}
	}

	if (!ifindex) {
		fprintf(stderr, "Please specify interface name\n");
		return -EINVAL;
	}
	if (!dhcp_server_addr_set) {
		fprintf(stderr, "Please specify DHCP server address with -d parameter\n");
		return -EINVAL;
	}
	if (!relay_agent_addr_set) {
		fprintf(stderr, "Please specify DHCP relay agent address with -s parameter\n");
		return -EINVAL;
	}

	if (do_unload)
		return xdp_link_detach(ifindex, xdp_flags);

	// Find MAC address of interface
	fd = socket(AF_INET, SOCK_DGRAM, 0);

	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, dev, IF_NAMESIZE);

	ioctl(fd, SIOCGIFHWADDR, &ifr);

	close(fd);

	mac = (unsigned char *) ifr.ifr_hwaddr.sa_data;

	__u64 hwaddr = 0;
	memcpy(&hwaddr, (unsigned char *) ifr.ifr_hwaddr.sa_data, 6);
	
	//display mac address
	printf("Using device %s MAC: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", dev, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	
	/* Load the BPF-ELF object file and get back first BPF_prog FD */
	err = bpf_prog_load(filename, BPF_PROG_TYPE_XDP, &obj, &prog_fd);
	if (err) {
		fprintf(stderr, "ERR: loading BPF-OBJ file(%s) (%d): %s\n",
			filename, err, strerror(-err));
		return -1;
	}
	if (prog_fd <= 0) {
		printf("ERR: loading file: %s\n", filename);
		return -1;
	}

	/* read the map from prog object file and update the real
	 * server IP to the map
	 */
	map = bpf_object__find_map_by_name(obj, SERVER_MAP);
	err = libbpf_get_error(map);
	if (err) {
		fprintf(stderr, "Could not find map %s in %s: %s\n", SERVER_MAP,
			XDP_OBJ, strerror(err));
		map = NULL;
		exit(-1);
	}
	map_fd = bpf_map__fd(map);
	if (map_fd < 0) {
		fprintf(stderr, "Could not get map fd\n");
		exit(-1);
	}

	// Set DHCP server address
	key = 0;
	err = bpf_map_update_elem(map_fd, &key, &dhcp_server_addr.s_addr, BPF_ANY);
	if (err) {
		fprintf(stderr, "Could not update map %s in %s\n", SERVER_MAP,
			XDP_OBJ);
		exit(-1);
	}

	// Set relay agent IP address
	key = 1;
	err = bpf_map_update_elem(map_fd, &key, &relay_agent_addr.s_addr, BPF_ANY);
	if (err) {
		fprintf(stderr, "Could not update map %s in %s\n", SERVER_MAP,
			XDP_OBJ);
		exit(-1);
	}
	
	// Set relay agent MAC address
	key = 2;
	err = bpf_map_update_elem(map_fd, &key, &hwaddr, BPF_ANY);
	if (err) {
		fprintf(stderr, "Could not update map %s in %s\n", SERVER_MAP,
			XDP_OBJ);
		exit(-1);
	}

	
	/* read the map from prog object file and update the real
	 * server IP to the map
	 */
	device_map = bpf_object__find_map_by_name(obj, DEVICE_MAP);
	err = libbpf_get_error(device_map);
	if (err) {
		fprintf(stderr, "Could not find map %s in %s: %s\n", DEVICE_MAP,
			XDP_OBJ, strerror(err));
		device_map = NULL;
		exit(-1);
	}
	device_map_fd = bpf_map__fd(device_map);
	if (device_map_fd < 0) {
		fprintf(stderr, "Could not get device map fd\n");
		exit(-1);
	}

	// Set device name in map
	key = 0;
	err = bpf_map_update_elem(device_map_fd, &key, dev, BPF_ANY);
	if (err) {
		fprintf(stderr, "Could not update map %s in %s\n", DEVICE_MAP,
			XDP_OBJ);
		exit(-1);
	}
	
	err = xdp_link_attach(ifindex, xdp_flags, prog_fd);
	if (err)
		return err;

	printf("Success: Loading xdp program\n");
	return 0;
}
