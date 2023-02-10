#include "tapkit.h"

#include "ds.h"
#include "tpool.h"
#include "utils.h"

NEW_CIRC_BUFFER(struct arp_entry, arp_buf, 256);

void tail_tap_handler(void* arg);
void print_eth_frame(const uint8_t* frame, const int len);

void emulate_tap_handler(void* arg);
void process_eth_frame(const struct tap_emulate_state* state, const uint8_t* frame, const int len);
int send_arp_reply(const char* dev_name, const uint8_t* target_mac, uint8_t* target_ip, const uint8_t* sender_mac, const uint8_t* sender_ip);

int knock_tap(char* dev_name) {
  const uint8_t target_mac[6] = {0x76, 0x54, 0x5b, 0x0d, 0x40, 0x49};
  uint8_t target_ip[6] = {192, 168, 42, 1};
  const uint8_t sender_mac[6] = {0x42, 0x42, 0x42, 0x42, 0x42, 0x42};
  const uint8_t sender_ip[4] = {192, 168, 42, 33};
  return send_arp_reply(
    dev_name,
    target_mac,
    target_ip,
    sender_mac,
    sender_ip
  );
}

int tail_tap(char* dev_name) {
  struct tap_dev dev = {
      .is_up = false, .dev_name = dev_name, .mac_addr = {0, 0, 0, 0, 0, 0}
  };

  if (get_tap_info(&dev) == -1) {
    fprintf(stderr, "could not find network device: %s\n", dev_name);
    return -1;
  }

  struct tap_tail_opts opts = {
      .dev = &dev,
      .func = print_eth_frame,
  };

  struct tpool* tm = tpool_create(1);
  tpool_add_work(tm, tail_tap_handler, &opts);
  tpool_wait(tm);
  tpool_destroy(tm);
  return 0;
}

int emulate_tap(char* dev_name, struct in_addr* ip) {
  struct tap_dev dev = {
      .is_up = false, .dev_name = dev_name, .mac_addr = {0, 0, 0, 0, 0, 0}
  };

  if (get_tap_info(&dev) == -1) {
    fprintf(stderr, "could not find network device: %s\n", dev_name);
    return -1;
  }

  struct tap_emulate_opts opts = {
      .dev = &dev,
      .ip = ip,
      .func = &process_eth_frame
  };

  struct tpool* tm = tpool_create(1);
  tpool_add_work(tm, emulate_tap_handler, &opts);
  tpool_wait(tm);
  tpool_destroy(tm);
  return 0;
}

void emulate_tap_handler(void* arg) {
  uint8_t frame[1542];
  fd_set rfds;
  struct timeval tv;
  struct tap_emulate_opts* opts = (struct tap_emulate_opts*)arg;

  print_tap_dev(opts->dev);
  const int tap_fd = open_tap(opts->dev->dev_name);
  if (tap_fd == -1) {
    goto cleanup;
  }

  // convert ip type to uint8_t array
  uint8_t o1, o2, o3, o4;
  uint32_t emu_addr = (uint32_t)opts->ip->s_addr;
  o1 = emu_addr & 0x000000ff;
  o2 = (emu_addr & 0x0000ff00) >> 8;
  o3 = (emu_addr & 0x00ff0000) >> 16;
  o4 = (emu_addr & 0xff000000) >> 24;

  const struct tap_emulate_state state = {
      .dev = opts->dev,
      .ip_addr = {o1, o2, o3, o4},
  };

  // read ethernet frames from tap device
  for (;;) {
    FD_ZERO(&rfds);
    FD_SET(tap_fd, &rfds);
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    int res = select(tap_fd + 1, &rfds, NULL, NULL, &tv);
    if (res < 0) {
      fprintf(stderr, "select failed: %s\n", strerror(errno));
      goto cleanup;
    }

    const int len = read(tap_fd, frame, sizeof(frame));
    if (len < 0) {
      fprintf(stderr, "read failed: %s\n", strerror(errno));
      continue;
    }

    opts->func(&state, frame, len);
  }
cleanup:
  if (tap_fd != -1) {
    close(tap_fd);
  }
}

void tail_tap_handler(void* arg) {
  uint8_t frame[1542];
  fd_set rfds;
  struct timeval tv;
  struct tap_tail_opts* opts = (struct tap_tail_opts*)arg;

  print_tap_dev(opts->dev);
  const int tap_fd = open_tap(opts->dev->dev_name);
  if (tap_fd == -1) {
    goto cleanup;
  }

  // read ethernet frames from tap device
  for (;;) {
    FD_ZERO(&rfds);
    FD_SET(tap_fd, &rfds);
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    int res = select(tap_fd + 1, &rfds, NULL, NULL, &tv);
    if (res < 0) {
      fprintf(stderr, "select failed: %s\n", strerror(errno));
      goto cleanup;
    }

    const int len = read(tap_fd, frame, sizeof(frame));
    if (len < 0) {
      fprintf(stderr, "read failed: %s\n", strerror(errno));
      continue;
    }

    opts->func(frame, len);
  }
cleanup:
  if (tap_fd != -1) {
    close(tap_fd);
  }
}

const int open_tap(char* dev_name) {
  const int tap_fd = open(TUN_DEV_PATH, O_RDWR);
  if (tap_fd == -1) {
    fprintf(stderr, "failed to open: "TUN_DEV_PATH" %s\n", strerror(errno));
    return -1;
  }

  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
  strncpy(ifr.ifr_name, dev_name, IFNAMSIZ);
  if (ioctl(tap_fd, TUNSETIFF, (void*)&ifr) < 0) {
    fprintf(stderr, "ioctl TUNSETIFF failed: %s\n", strerror(errno));
    if (close(tap_fd) == -1) {
      fprintf(stderr, "failed to close: /dev/net/tun: %s\n", strerror(errno));
    }
    return -1;
  }

  return tap_fd;
}

const int get_tap_info(struct tap_dev* dev) {
  char p_errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *interfaces, *interface;
  int result = 0;
  bool is_up;

  if (pcap_findalldevs(&interfaces, p_errbuf) == PCAP_ERROR) {
    fprintf(stderr, "failed to find network devices: %s\n", p_errbuf);
    return -1;
  }

  for (interface = interfaces; interface; interface = interface->next) {
    if (strcmp(interface->name, dev->dev_name) == 0) {
      goto getinfo;
    }
  }
  result = -1;
  goto cleanup;

getinfo:
  is_up = (interface->flags & PCAP_IF_UP) == PCAP_IF_UP;
  dev->is_up = is_up;
  struct pcap_addr* address = NULL;
  for (address = interface->addresses; address != NULL;
       address = address->next) {
    if (address->addr->sa_family == AF_PACKET &&
        address->addr->sa_data != NULL) {
      // FIND out the correct type to cast this to
      uint8_t* addr = (uint8_t*)address->addr->sa_data;
      memcpy(dev->mac_addr, (addr + 10), sizeof(uint8_t) * 6);
      break;
    }
  }

cleanup:
  pcap_freealldevs(interfaces);
  return result;
}

void print_eth_frame(const uint8_t* frame, const int len) {
  if (len < 0) {
    fprintf(stderr, "read failed: %s\n", strerror(errno));
    return;
  }

  const struct ethhdr* ethhdr = (struct ethhdr*)frame;
  uint16_t ether_type = ntohs(ethhdr->h_proto);
  switch (ether_type) {
    case IPV4_ETHER_TYPE: {
      fprintf(stdout, "IPv4 PACKET\n");
      break;
    }
    case ARP_ETHER_TYPE: {
      if (len != SIZE_ETHERNET + SIZE_ARP) {
        fprintf(stderr, "invalid arp packet length: %d\n", len);
        return;
      }

      const struct arp_fields* fields =
          (struct arp_fields*)(frame + SIZE_ETHERNET);
      uint16_t ptype = ntohs(fields->ptype);
      if (ptype != IPV4_ETHER_TYPE) {
        fprintf(stderr, "unsupported arp protocol type: 0x%.04x\n", ptype);
        return;
      }

      print_arp_packet(ethhdr, fields);
      break;
    }
    default: {
      break;
    }
  }
}

/**
 * Send an ARP reply using a particular network device.
 *
 * An ARP reply is used to forward the MAC address of a target host that was
 * requested by a sender host.
 *
 * const char*    dev_name   - The name of the network device that will send the reply.
 * const uint8_t* target_mac - The MAC address of host that originated ARP request.
 * uint8_t* target_ip  - The IP address of host that originated ARP request.
 * const uint8_t* sender_mac - The MAC address of host that was requested.
 * const uint8_t* sender_ip  - The IP address of host that was requested.
 */
int send_arp_reply(
  const char* dev_name,
  const uint8_t* target_mac, uint8_t* target_ip,
  const uint8_t* sender_mac, const uint8_t* sender_ip
) {
  libnet_t* ctx = NULL;                 /* libnet context */
  pcap_t* handle = NULL;                /* libnet handle  */
  libnet_ptag_t arp = 0, eth = 0;       /* libnet protocol blocks */
  struct libnet_ether_addr* source_mac; /* MAC address for sending device */
  char n_errbuf[LIBNET_ERRBUF_SIZE];    /* error messages */
  char p_errbuf[PCAP_ERRBUF_SIZE];      /* error messages */
  int r = 0;                            /* generic return value */
  int maclen;

  /* Open libnet handle */
  ctx = libnet_init(LIBNET_LINK_ADV, dev_name, n_errbuf);
  if (ctx == NULL) {
    fprintf(stderr, "error: %s", n_errbuf);
    r = -1;
    goto cleanup;
  }

  // // Put the IP addresses in network byte order
  // uint8_t n_sender_ip[4] = {sender_ip[3], sender_ip[2], sender_ip[1], sender_ip[0]};
  // uint8_t n_target_ip[4] = {target_ip[3], target_ip[2], target_ip[1], target_ip[0]};

  /* Build the ARP header */
  arp = libnet_autobuild_arp(ARPOP_REPLY, sender_mac, sender_ip, target_mac, target_ip, ctx);
  if (arp == -1) {
    fprintf(stderr, "unable to build ARP header: %s\n", libnet_geterror(ctx));
    r = -1;
    goto cleanup;
  }

  source_mac = libnet_get_hwaddr(ctx);

  /* Build the Ethernet header */
  eth = libnet_build_ethernet(target_mac, source_mac->ether_addr_octet, ETHERTYPE_ARP, NULL, 0, ctx, 0);
  if (eth == -1) {
    fprintf(stderr, "unable to build ethernet header: %s\n",
            libnet_geterror(ctx));
    r = -1;
    goto cleanup;
  }

  /* Generate the network packet */
  uint8_t* packet = NULL;
  uint32_t packet_size = 0;
  if (libnet_adv_cull_packet(ctx, &packet, &packet_size) == -1) {
    fprintf(stderr, "unable to read packet: %s\n", libnet_geterror(ctx));
    r = -1;
    goto cleanup;
  }

  /* Open the network device that will send the packet */
  handle = pcap_open_live(dev_name, BUFSIZ, 1, 1000, p_errbuf);
  if (handle == NULL) {
    fprintf(stderr, "could not open device %s: %s\n", dev_name, p_errbuf);
    r = -1;
    goto cleanup;
  }

  /* Send the packet using the network device */
  if (pcap_sendpacket(handle, (uint8_t*)packet, packet_size) == PCAP_ERROR) {
    fprintf(stderr, "failed to send packet: %s\n", p_errbuf);
    r = -1;
    goto cleanup;
  }

cleanup:
  if (ctx != NULL) {
    if (packet != NULL) {
      libnet_adv_free_packet(ctx, packet);
    }
    libnet_destroy(ctx);
  }
  if (handle != NULL) {
    pcap_close(handle);
  }
  return r;
}

void process_eth_frame(const struct tap_emulate_state* state, const uint8_t* frame, const int len)
{
  if (len < 0) {
    fprintf(stderr, "read failed: %s\n", strerror(errno));
    return;
  }

  const struct ethhdr* ethhdr = (struct ethhdr*)frame;
  uint16_t ether_type = ntohs(ethhdr->h_proto);
  switch (ether_type) {
    case IPV4_ETHER_TYPE: {
      fprintf(stdout, "IPv4 PACKET\n");
      break;
    }

    case ARP_ETHER_TYPE: {
      if (len != SIZE_ETHERNET + SIZE_ARP) {
        fprintf(stderr, "invalid arp packet length: %d\n", len);
        return;
      }

      const struct arp_fields* fields =
          (struct arp_fields*)(frame + SIZE_ETHERNET);
      uint16_t ptype = ntohs(fields->ptype);
      if (ptype != IPV4_ETHER_TYPE) {
        fprintf(stderr, "unsupported arp protocol type: 0x%.04x\n", ptype);
        return;
      }

      bool is_request = ntohs(fields->oper) == 1;
      if (is_request) { // ARP Request
        // Ensure the target IP address is our IP address
        if (!ip_addrs_eq(fields->tpa, state->ip_addr)) {
            return;
        }

        send_arp_reply(
          state->dev->dev_name,
          fields->sha,
          fields->spa,
          state->dev->mac_addr,
          fields->tpa
        );
      } else { // ARP Reply
        // Ensure that the target MAC address is our MAC address
        if (!mac_addrs_eq(fields->tha, state->dev->mac_addr)) {
            return;
        }

        // Ensure the target IP address is our IP address
        if (!ip_addrs_eq(fields->tpa, state->ip_addr)) {
            return;
        }
      }

      // Create an entry that assoicates an IP addr with a MAC addr
      struct arp_entry new_entry = {
        .ip_addr={fields->spa[0],fields->spa[1],fields->spa[2],fields->spa[3]},
        .mac_addr={fields->sha[0],fields->sha[1],fields->sha[2],fields->sha[3],fields->sha[4],fields->sha[5]},
      };

      // TODO: Make this a hash map instead...
      CIRC_BUFFER_PUSH(arp_buf, &new_entry);

      print_arp_packet(ethhdr, fields);
      break;
    }
    default: {
      break;
    }
  }
}