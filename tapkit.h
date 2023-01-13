#ifndef _TAPKIT_H_
#define _TAPKIT_H_

#include "common.h"

typedef void (*tap_tail_func_t)(const uint8_t* frame, const int len);

struct tap_dev {
  char* dev_name;
  bool is_up;
  u_char mac_addr[6];
};

struct tap_tail_opts {
  const struct tap_dev* dev;
  tap_tail_func_t func;
};

/* IP header */
struct sniff_ip {
  u_char ip_vhl;                 /* version << 4 | header length >> 2 */
  u_char ip_tos;                 /* type of service */
  u_short ip_len;                /* total length */
  u_short ip_id;                 /* identification */
  u_short ip_off;                /* fragment offset field */
#define IP_RF 0x8000             /* reserved fragment flag */
#define IP_DF 0x4000             /* don't fragment flag */
#define IP_MF 0x2000             /* more fragments flag */
#define IP_OFFMASK 0x1fff        /* mask for fragmenting bits */
  u_char ip_ttl;                 /* time to live */
  u_char ip_p;                   /* protocol */
  u_short ip_sum;                /* checksum */
  struct in_addr ip_src, ip_dst; /* source and dest address */
};

#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip) (((ip)->ip_vhl) >> 4)

/* ICMP header*/
struct sniff_icmp {
  u_char icmp_type;
  u_char icmp_code;
  u_short icmp_checksum;
  u_int32_t icmp_rest_of_header;
};

struct icmp_echo_header {
  u_short icmp_identifier;
  u_short icmp_seq_num;
};

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
  u_short th_sport; /* source port */
  u_short th_dport; /* destination port */
  tcp_seq th_seq;   /* sequence number */
  tcp_seq th_ack;   /* acknowledgement number */
  u_char th_offx2;  /* data offset, rsvd */
#define TH_OFF(th) (((th)->th_offx2 & 0xf0) > 4)
  u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN | TH_SYN | TH_RST | TH_ACK | TH_URG | TH_ECE | TH_CWR)
  u_short th_win; /* window */
  u_short th_sum; /* checksum */
  u_short th_urp; /* urgent pointer */
};

int tail_tap(char* dev_name);

int knock_tap(char* dev_name);

const int open_tap(char* dev_name);

void print_tap_dev(const struct tap_dev* dev);

const int get_tap_info(struct tap_dev* dev);

#endif