#ifndef _TAPKIT_UTILS_H_
#define _TAPKIT_UTILS_H_

#include "common.h"

int arp_sender_mac_str(struct arp_fields* fields, char* str);

int arp_target_mac_str(struct arp_fields* fields, char* str);

int arp_sender_ip_str(struct arp_fields* fields, char* str);

int arp_target_ip_str(struct arp_fields* fields, char* str);

#endif