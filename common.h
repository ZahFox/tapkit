#ifndef _TAPKIT_COMMON_H_
#define _TAPKIT_COMMON_H_

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <libnet.h>
#include <linux/if_tun.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_packet.h>
#include <netinet/ether.h>
#include <pcap.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <unistd.h>

/* The maximum length of an IPv4 string, e.g., "255.255.255.255"  */
#define IPV4_STR_MAXLEN 18

/* Ethernet headers are always exactly 14 bytes */
#define SIZE_ETHERNET 14

/* ARP packets are always exactly 28 bytes */
#define SIZE_ARP 28

/* ICMP headers are always exactly 8 bytes */
#define SIZE_ICMP 8

/*
 * The number of characters to represent a MAC address string
 * including the null byte at the end. e.g., "aa:bb:cc:dd:ee:ff"
 */
#define MAC_ADDR_STR_LEN 18

enum ether_type { IPV4_ETHER_TYPE = 0x0800, ARP_ETHER_TYPE = 0x0806 };

struct tap_dev {
  char* dev_name;
  bool is_up;
  uint8_t mac_addr[6];
};

struct arp_entry {
  const uint8_t ip_addr[4];
  const uint8_t mac_addr[6];
};

struct arp_fields {
  const uint16_t htype; /* Hardware Type */
  const uint16_t ptype; /* Protocol Type */
  const uint8_t hlen;   /* Hardware Address Length */
  const uint8_t plen;   /* Protocol Address Length */
  const uint16_t oper;  /* Operation 1 for request 2 for reply */
  const uint8_t sha[6]; /* Sender Hardware Address */
  const uint8_t spa[4]; /* Sender Protocol Address */
  const uint8_t tha[6]; /* Target Hardware Address */
  const uint8_t tpa[4]; /* Target Protocol Address */
};

#endif