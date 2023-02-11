#include "utils.h"

void print_arp_packet(const struct ethhdr* ethhdr,
                      const struct arp_fields* fields)
{
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

bool mac_addrs_eq(const uint8_t* l, const uint8_t* r) {
    return l[0] == r[0] && l[1] == r[1] && l[2] == r[2] && l[3] == r[3] && l[4] == r[4] && l[5] == r[5];
}

bool ipv4_addrs_eq(const uint8_t* l, const uint8_t* r) {
    return l[0] == r[0] && l[1] == r[1] && l[2] == r[2] && l[3] == r[3];
}

/**
 * Convert an IPv4 address string into a uint8_t[4].
 */
int ipv4_str_to_addr(char* ip_str, uint8_t* ip_addr) {
    struct in_addr ip;
    if (inet_pton(AF_INET, ip_str, &ip) == 0) {
        return -1;
    }

    ipv4_naddr_to_addr(&ip, ip_addr);
    return 0;
}

/**
 * Convert an network encoded IPv4 address into a uint8_t[4].
 */
void ipv4_naddr_to_addr(struct in_addr* ip_naddr, uint8_t* ip_addr) {
  uint32_t emu_addr = (uint32_t)ip_naddr->s_addr;
  ip_addr[0] = emu_addr & 0x000000ff;
  ip_addr[1] = (emu_addr & 0x0000ff00) >> 8;
  ip_addr[2] = (emu_addr & 0x00ff0000) >> 16;
  ip_addr[3] = (emu_addr & 0xff000000) >> 24;
}