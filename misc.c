#include "tapkit.h"
#include "tpool.h"

/* Convert 16 bits from big-endian to little-endian  */
#define TO_LITTLE_ENDIAN_16(x) ((x >> 8) | (x << 8));

/* Convert 32 bits from big-endian to little-endian  */
#define TO_LITTLE_ENDIAN_32(x)                          \
  (((x >> 24) & 0x000000ff) | ((x << 8) & 0x00ff0000) | \
   ((x >> 8) & 0x0000ff00) | ((x << 24) & 0xff000000));

/* Convert 48 bits from big-endian to little-endian  */
#define TO_LITTLE_ENDIAN_48(x)                                   \
  (((x & 0x0000000000ff) << 40) | ((x & 0x00000000ff00) << 24) | \
   ((x & 0x000000ff0000) << 8) | ((x & 0x0000ff000000) >> 8) |   \
   ((x & 0x00ff00000000) >> 24) | ((x & 0xff0000000000) >> 40));

/* Ethernet header */
struct ethernet_hdrs {
  uint8_t ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
  uint8_t ether_shost[ETHER_ADDR_LEN]; /* Source host address */
  uint16_t ether_type;                 /* IP? ARP? RARP? etc */
};

int legacy_tail_tap2(char* dev_name) {
  int n;
  int ret = 0;
  int sock;
  char buf[2048];
  struct ifreq ifreq;
  struct sockaddr_ll saddr;

  // create socket that receieves raw layer-2 network data for all protocols
  if ((sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
    ret = errno;
    goto error_exit;
  }

  // bind tap0
  snprintf(ifreq.ifr_name, sizeof(ifreq.ifr_name), "%s", dev_name);
  if (ioctl(sock, SIOCGIFINDEX, &ifreq)) {
    ret = errno;
    goto error_exit;
  }

  memset(&saddr, 0, sizeof(saddr));
  saddr.sll_family = AF_PACKET;
  saddr.sll_protocol = htons(ETH_P_ALL);
  saddr.sll_ifindex = ifreq.ifr_ifindex;
  saddr.sll_pkttype = PACKET_HOST;

  if (bind(sock, (struct sockaddr*)&saddr, sizeof(saddr)) == -1) {
    ret = errno;
    goto error_exit;
  }

  // recv data
  while (1) {
    n = recvfrom(sock, buf, sizeof(buf), 0, NULL, NULL);
    printf("%d bytes recieved\n", n);
  }

error_exit:
  if (ret) {
    printf("error: %s (%d)\n", strerror(ret), ret);
  }
  close(sock);
  return ret;
}

void got_icmp_packet(uint8_t* args, const struct pcap_pkthdr* header,
                     const uint8_t* packet) {
  const struct ethernet_hdrs* ethernet; /* The Ethernet header */
  const struct ipv4_fields* ip;         /* The IP header */
  const struct icmp_fields* icmp;       /* The ICMP header */
  const char* payload;                  /* Packet payload */
  u_int size_ip;

  ethernet = (struct ethernet_hdrs*)(packet);
  ip = (struct ipv4_fields*)(packet + SIZE_ETHERNET);
  size_ip = IP_HL(ip) * 4;
  if (size_ip < 20) {
    fprintf(stderr, "invalid IP header length: %u bytes\n", size_ip);
    return;
  }

  icmp = (struct icmp_fields*)(packet + SIZE_ETHERNET + size_ip);
  payload = (uint8_t*)(packet + SIZE_ETHERNET + size_ip + SIZE_ICMP);

  if (icmp->icmp_type == 8) { /* Echo Request */
    struct icmp_echo_header* echo_hdrs;
    echo_hdrs = (struct icmp_echo_header*)&icmp->icmp_rest_of_header;
    uint8_t ident = TO_LITTLE_ENDIAN_16(echo_hdrs->icmp_identifier);
    uint8_t seq_num = TO_LITTLE_ENDIAN_16(echo_hdrs->icmp_seq_num);
    fputs("echo request, ", stdout);
    fprintf(stdout, "id %hu, seq %hu\n", ident, seq_num);

  } else if (icmp->icmp_type == 0) { /* Echo Reply */
    struct icmp_echo_header* echo_hdrs;
    echo_hdrs = (struct icmp_echo_header*)&icmp->icmp_rest_of_header;
    uint8_t ident = TO_LITTLE_ENDIAN_16(echo_hdrs->icmp_identifier);
    uint8_t seq_num = TO_LITTLE_ENDIAN_16(echo_hdrs->icmp_seq_num);
    fputs("echo reply, ", stdout);
    fprintf(stdout, "id %hu, seq %hu\n", ident, seq_num);
  }
}

int tail_icmp(char* dev_name) {
  if (print_dev_info(dev_name) == -1) {
    return -1;
  }

  pcap_t* handle;
  struct pcap_pkthdr header;
  const uint8_t* packet;
  char errbuf[PCAP_ERRBUF_SIZE];
  char filter_exp[] = "icmp"; /* The filter expression */
  struct bpf_program fp;      /* The compiled filter */
  bpf_u_int32 net;            /* Our IP */

  handle = pcap_open_live(dev_name, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "could not open device %s: %s\n", dev_name, errbuf);
    return -1;
  }

  if (pcap_datalink(handle) != DLT_EN10MB) {
    fprintf(stderr,
            "device %s does not provide ethernet headers - not supported\n",
            dev_name);
    return -1;
  }

  /* Compile and apply the filter */
  if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
    fprintf(stderr, "could not parse filter %s: %s\n", filter_exp,
            pcap_geterr(handle));
    return -1;
  }

  if (pcap_setfilter(handle, &fp) == -1) {
    fprintf(stderr, "could not install filter %s: %s\n", filter_exp,
            pcap_geterr(handle));
    return -1;
  }

  pcap_loop(handle, -1, got_icmp_packet, NULL);

  /* close the packet capture session */
  pcap_close(handle);

  return EXIT_SUCCESS;
}

void emulate(void) {
  struct tpool* tm;
  int vals[100];
  size_t i;

  tm = tpool_create(4);

  for (i = 0; i < 100; i++) {
    vals[i] = i;
    tpool_add_work(tm, worker, &(vals[i]));
  }

  tpool_wait(tm);

  uint64_t sum = 0;
  for (i = 0; i < 100; i++) {
    sum += vals[i];
  }
  fprintf(stdout, "%lu (%d)\n", sum, sum == 104950);

  tpool_destroy(tm);
}

int old_print_dev_info(char* dev_name) {
  char* dev;  /* name of the device to use */
  char* net;  /* dot notation of the network address */
  char* mask; /* dot notation of the network mask    */
  int ret;    /* return code */
  char errbuf[PCAP_ERRBUF_SIZE];
  bpf_u_int32 netp;  /* ip          */
  bpf_u_int32 maskp; /* subnet mask */
  struct in_addr addr;

  /* error checking */
  if (dev_name == NULL) {
    printf("%s\n", errbuf);
    return -1;
  }

  /* print out device name */
  printf("DEV: %s\n", dev_name);

  pcap_look

      /* ask pcap for the network address and mask of the device */
      ret = pcap_lookupnet(dev_name, &netp, &maskp, errbuf);

  if (ret == -1) {
    printf("%s\n", errbuf);
    return EXIT_SUCCESS;
  }

  /* get the network address in a human readable form */
  addr.s_addr = netp;
  net = inet_ntoa(addr);
  if (net == NULL) /* thanks Scott :-P */
  {
    perror("inet_ntoa");
    return -1;
  }

  printf("NET: %s\n", net);

  /* do the same as above for the device's mask */
  addr.s_addr = maskp;
  mask = inet_ntoa(addr);

  if (mask == NULL) {
    perror("inet_ntoa");
    return -1;
  }

  printf("MASK: %s\n", mask);
  return EXIT_SUCCESS;
}