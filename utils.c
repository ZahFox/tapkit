#include "utils.h"

int mac_to_str(uint64_t mac, char* str) {
  int str_len =
      snprintf(str, MAC_ADDR_STR_LEN,
               "%.2" PRIx64 ":%.2" PRIx64 ":%.2" PRIx64 ":%.2" PRIx64
               ":%.2" PRIx64 ":%.2" PRIx64,
               (mac & 0xff0000000000) >> 40, (mac & 0x00ff00000000) >> 32,
               (mac & 0x0000ff000000) >> 24, (mac & 0x000000ff0000) >> 16,
               (mac & 0x00000000ff00) >> 8, (mac & 0x0000000000ff));
  return str_len;
}

// int arp_sender_mac_str(struct arp_fields* fields, char* str) {
//   uint16_t sha_0 = ntohs(fields->sha_0);
//   uint16_t sha_2 = ntohs(fields->sha_2);
//   uint16_t sha_4 = ntohs(fields->sha_4);
//   uint64_t sender =
//       ((uint64_t)sha_0 << 32) | ((uint64_t)sha_2 << 16) | ((uint64_t)sha_4);
//   return mac_to_str(sender, str);
// }

// int arp_target_mac_str(struct arp_fields* fields, char* str) {
//   uint16_t tha_0 = ntohs(fields->tha_0);
//   uint16_t tha_2 = ntohs(fields->tha_2);
//   uint16_t tha_4 = ntohs(fields->tha_4);
//   uint64_t target =
//       ((uint64_t)tha_0 << 32) | ((uint64_t)tha_2 << 16) | ((uint64_t)tha_4);
//   return mac_to_str(target, str);
// }

// int arp_sender_ip_str(struct arp_fields* fields, char* str) {
//   char* inet_str = inet_ntoa(fields->spa);
//   if (inet_str == NULL) {
//     return EXIT_FAILURE;
//   }
//   strcpy(str, inet_str);
// }

// int arp_target_ip_str(struct arp_fields* fields, char* str) {
//   char* inet_str = inet_ntoa(fields->tpa);
//   if (inet_str == NULL) {
//     return EXIT_FAILURE;
//   }
//   strcpy(str, inet_str);
// }