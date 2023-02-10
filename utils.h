#ifndef _TAPKIT_UTILS_H_
#define _TAPKIT_UTILS_H_

#include "common.h"

void print_arp_packet(const struct ethhdr* ethhdr,
                      const struct arp_fields* fields);

void print_tap_dev(const struct tap_dev* dev);

bool mac_addrs_eq(const uint8_t* l, const uint8_t* r);

bool ip_addrs_eq(const uint8_t* l, const uint8_t* r);

#endif