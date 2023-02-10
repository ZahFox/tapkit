#include "tapkit.h"

#include "tpool.h"
#include "utils.h"

#define TUN_DEV_PATH "/dev/net/tun"

void tail_tap_handler(void* arg);
void log_eth_frame(const uint8_t* frame, const int len);

void emulate_tap_handler(void* arg);
void process_eth_frame(const struct tap_emulate_state* state, const uint8_t* frame, const int len);

int knock_tap(char* dev_name) {
  in_addr_t source_ip;  /* claimed ip address */
  in_addr_t target_ip;  /* destination ip address */
  uint8_t* target_mac; /* destination mac address */
  libnet_t* ctx = NULL; /* libnet context */
  pcap_t* handle = NULL;
  libnet_ptag_t arp = 0, eth = 0;       /* libnet protocol blocks */
  struct libnet_ether_addr* source_mac; /* ethernet MAC address */
  char n_errbuf[LIBNET_ERRBUF_SIZE];    /* error messages */
  char p_errbuf[PCAP_ERRBUF_SIZE];      /* error messages */
  int r = EXIT_SUCCESS;                 /* generic return value */
  int maclen;

  source_ip = inet_addr("192.168.42.33");
  target_ip = inet_addr("192.168.42.1");
  if ((target_mac = libnet_hex_aton("76:54:5b:0d:40:49", &maclen)) == NULL) {
    fprintf(stderr, "mac address error");
    goto cleanup;
  }

  /* open handle */
  ctx = libnet_init(LIBNET_LINK_ADV, dev_name, n_errbuf);

  if (ctx == NULL) {
    fprintf(stderr, "error: %s", n_errbuf);
    r = -1;
    goto cleanup;
  }

  source_mac = libnet_get_hwaddr(ctx);
  /* build the ARP header */
  arp = libnet_autobuild_arp(ARPOP_REPLY,           /* operation */
                             (uint8_t*)source_mac, /* source hardware addr */
                             (uint8_t*)&source_ip, /* source protocol addr */
                             target_mac,            /* target hardware addr */
                             (uint8_t*)&target_ip, /* target protocol addr */
                             ctx);                  /* libnet context */

  if (arp == -1) {
    fprintf(stderr, "unable to build ARP header: %s\n", libnet_geterror(ctx));
    r = -1;
    goto cleanup;
  }

  /* build the ethernet header */
  eth = libnet_build_ethernet(target_mac,            /* destination address */
                              (uint8_t*)source_mac, /* source address */
                              ETHERTYPE_ARP, /* type of encasulated packet */
                              NULL,          /* pointer to payload */
                              0,             /* size of payload */
                              ctx,           /* libnet context */
                              0);            /* libnet protocol tag */

  if (eth == -1) {
    fprintf(stderr, "unable to build ethernet header: %s\n",
            libnet_geterror(ctx));
    r = -1;
    goto cleanup;
  }

  uint8_t* packet = NULL;
  uint32_t packet_size = 0;
  if (libnet_adv_cull_packet(ctx, &packet, &packet_size) == -1) {
    fprintf(stderr, "unable to read packet: %s\n", libnet_geterror(ctx));
    r = -1;
    goto cleanup;
  }

  handle = pcap_open_live(dev_name, BUFSIZ, 1, 1000, p_errbuf);
  if (handle == NULL) {
    fprintf(stderr, "could not open device %s: %s\n", dev_name, p_errbuf);
    r = -1;
    goto cleanup;
  }

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

int tail_tap(char* dev_name) {
  struct tap_dev dev = {
      .is_up = false, .dev_name = dev_name, .mac_addr = {0, 0, 0, 0, 0, 0}};

  if (get_tap_info(&dev) == -1) {
    fprintf(stderr, "could not find network device: %s\n", dev_name);
    return -1;
  }

  struct tap_tail_opts opts = {
      .dev = &dev,
      .func = log_eth_frame,
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

  const struct tap_emulate_state state = {
      .dev = opts->dev,
      .ip = opts->ip,
  };

  // read ethernet frames from tap device
  for (;;) {
    FD_ZERO(&rfds);
    FD_SET(tap_fd, &rfds);
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    int res = select(tap_fd + 1, &rfds, NULL, NULL, &tv);
    if (res < 0) {
      fprintf(stderr, "select fails: %s\n", strerror(errno));
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
      fprintf(stderr, "select fails: %s\n", strerror(errno));
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

void print_tap_dev(const struct tap_dev* dev) {
  fputs("========================================\n", stdout);
  fprintf(stdout, "%s\n", dev->dev_name);
  fputs("========================================\n", stdout);
  fprintf(stdout, "Up: %s\n", dev->is_up ? "True" : "False");
  fprintf(stdout, "MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", dev->mac_addr[0],
          dev->mac_addr[1], dev->mac_addr[2], dev->mac_addr[3],
          dev->mac_addr[4], dev->mac_addr[5]);
  fputs("----------------------------------------\n", stdout);
}

void log_eth_frame(const uint8_t* frame, const int len) {
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

      fprintf(stdout,
              "========================================\n"
              "ARP %s\n"
              "========================================\n",
              ntohs(fields->oper) == 1 ? "Request" : "Reply");
      fprintf(stdout,
              "To:    %02x:%02x:%02x:%02x:%02x:%02x\n"
              "From:  %02x:%02x:%02x:%02x:%02x:%02x\n",
              ethhdr->h_dest[0], ethhdr->h_dest[1], ethhdr->h_dest[2],
              ethhdr->h_dest[3], ethhdr->h_dest[4], ethhdr->h_dest[5],
              ethhdr->h_source[0], ethhdr->h_source[1], ethhdr->h_source[2],
              ethhdr->h_source[3], ethhdr->h_source[4], ethhdr->h_source[5]);

      fprintf(stdout,
              "MAC:\n"
              "  Sender:    %02x:%02x:%02x:%02x:%02x:%02x\n"
              "  Target:    %02x:%02x:%02x:%02x:%02x:%02x\n",
              fields->sha[0], fields->sha[1], fields->sha[2], fields->sha[3],
              fields->sha[4], fields->sha[5], fields->tha[0], fields->tha[1],
              fields->tha[2], fields->tha[3], fields->tha[4], fields->tha[5]);

      fprintf(stdout,
              "IP:\n"
              "  Sender:    %u.%u.%u.%u\n"
              "  Target:    %u.%u.%u.%u\n",
              fields->spa[0], fields->spa[1], fields->spa[2], fields->spa[3],
              fields->tpa[0], fields->tpa[1], fields->tpa[2], fields->tpa[3]);
      fputs("----------------------------------------\n", stdout);
      break;
    }
    default: {
      break;
    }
  }
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
      if (is_request) { // ARP REQUEST
        // Target: The host that has the requested IP
        // TPA -> IP address we are trying to find HW address of
        // THA -> Ignored (this is what we want to find out)
        // Sender: The host that requested the HW address for IP
        // SPA -> IP address of the host that originated ARP req
        // SHA -> HW address of the host that originated ARP req
      } else { // ARP REPLY
        // Target: The host that requested the HW address for IP
        // TPA -> HW address of host that originated ARP req
        // THA -> HW address of host that originated ARP req
        // Sender: The host that has the requested IP
        // SPA -> The IP address of the host we wanted to find
        // SHA -> The HW address of the host we wanted to find

        // Ensure that the target MAC address matches our MAC address
        if (
          (fields->tha[0] != state->dev->mac_addr[0]) || (fields->tha[1] != state->dev->mac_addr[1]) ||
          (fields->tha[2] != state->dev->mac_addr[2]) || (fields->tha[3] != state->dev->mac_addr[3]) ||
          (fields->tha[4] != state->dev->mac_addr[4]) || (fields->tha[5] != state->dev->mac_addr[5])
        ) {
              return;
        }

        uint8_t o1, o2, o3, o4;
        uint32_t emu_addr = (uint32_t)state->ip->s_addr;
        o1 = emu_addr & 0x000000ff;
        o2 = (emu_addr & 0x0000ff00) >> 8;
        o3 = (emu_addr & 0x00ff0000) >> 16;
        o4 = (emu_addr & 0xff000000) >> 24;

        // Ensure the target IP address matches our IP address
        if (
          (fields->tpa[0] != o1) || (fields->tpa[1] != o2) ||
          (fields->tpa[2] != o3)  || (fields->tpa[3] != o4)
        ) {
          return;
        }
      }

      fprintf(stdout,
              "========================================\n"
              "ARP %s\n"
              "========================================\n",
              ntohs(fields->oper) == 1 ? "Request" : "Reply");
      fprintf(stdout,
              "To:    %02x:%02x:%02x:%02x:%02x:%02x\n"
              "From:  %02x:%02x:%02x:%02x:%02x:%02x\n",
              ethhdr->h_dest[0], ethhdr->h_dest[1], ethhdr->h_dest[2],
              ethhdr->h_dest[3], ethhdr->h_dest[4], ethhdr->h_dest[5],
              ethhdr->h_source[0], ethhdr->h_source[1], ethhdr->h_source[2],
              ethhdr->h_source[3], ethhdr->h_source[4], ethhdr->h_source[5]);

      fprintf(stdout,
              "MAC:\n"
              "  Sender:    %02x:%02x:%02x:%02x:%02x:%02x\n"
              "  Target:    %02x:%02x:%02x:%02x:%02x:%02x\n",
              fields->sha[0], fields->sha[1], fields->sha[2], fields->sha[3],
              fields->sha[4], fields->sha[5], fields->tha[0], fields->tha[1],
              fields->tha[2], fields->tha[3], fields->tha[4], fields->tha[5]);

      fprintf(stdout,
              "IP:\n"
              "  Sender:    %u.%u.%u.%u\n"
              "  Target:    %u.%u.%u.%u\n",
              fields->spa[0], fields->spa[1], fields->spa[2], fields->spa[3],
              fields->tpa[0], fields->tpa[1], fields->tpa[2], fields->tpa[3]);
      fputs("----------------------------------------\n", stdout);
      break;
    }
    default: {
      break;
    }
  }
}