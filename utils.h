#ifndef _TAPKIT_UTILS_H_
#define _TAPKIT_UTILS_H_

#include "common.h"

void print_arp_packet(const struct ethhdr* ethhdr,
                      const struct arp_fields* fields);

void print_tap_dev(const struct tap_dev* dev);

bool mac_addrs_eq(const uint8_t* l, const uint8_t* r);

bool ipv4_addrs_eq(const uint8_t* l, const uint8_t* r);

int ipv4_str_to_addr(char* ip_str, uint8_t* ip_addr);

void ipv4_naddr_to_addr(struct in_addr* ip_naddr, uint8_t* ip_addr);

#endif