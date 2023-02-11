#include "cunittests.h"
#include "tapkit.h"

#ifndef TESTING
int main(int argc, char* argv[]) {
  if (argc < 2) {
    fputs("tapkit: missing operand\nTry 'tapkit --help' for more information\n", stderr);
    return EXIT_FAILURE;
  }

  int res = 0;
  char* cmd = argv[1];
  for (char* p = cmd; *p; p++) *p = tolower(*p);

  if (!strcmp(cmd, "tail")) {
    if (argc < 3) {
      fprintf(stderr, "tapkit: error: specify a tap device to tail\n");
      return EXIT_FAILURE;
    }

    char* dev = argv[2];
    res = tail_tap(dev);
  } else if (!strcmp(cmd, "knock")) {
    if (argc < 3) {
      fprintf(stderr, "tapkit: error: specify a tap device to knock\n");
      return EXIT_FAILURE;
    }

    char* dev = argv[2];
    res = knock_tap(dev);
  } else if (!strcmp(cmd, "emulate")) {
    if (argc < 4) {
      fprintf(stderr, "tapkit: error: specify a tap device and ip address\n");
      return EXIT_FAILURE;
    }

    char* dev = argv[2];
    struct in_addr ip;
    if (inet_pton(AF_INET, argv[3], &ip) == 0) {
      fprintf(stderr, "tapkit: error: invalid ip address\n");
      return EXIT_FAILURE;
    }

    res = emulate_tap(dev, &ip);
  } else if (!strcmp(cmd, "--help")) {
    fputs("Usage: tapkit COMMAND\n       tapkit --help\nwhere  COMMAND := { tail | knock | emulate }\n", stdout);
  } else {
    fprintf(stderr, "tapkit: invalid command: %s\nTry 'tapkit --help' for more information\n", cmd);
    return EXIT_FAILURE;
  }

  if (res == 0) {
    return EXIT_SUCCESS;
  }

  return EXIT_FAILURE;
}
#else
int main(void) { return cunittester(); }
#endif