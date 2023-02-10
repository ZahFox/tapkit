# tapkit

This repository contains `tapkit`, a simple tool for reading and writing Ethernet frames to [TAP devices](https://en.wikipedia.org/wiki/TUN/TAP).

## Getting Started

### Dependencies

Building `tapkit` requires the 3 following dependencies:

- [CUnit](https://github.com/the-tcpdump-group/libpcap)
- [libpcap](https://github.com/the-tcpdump-group/libpcap)
- [libnet](https://github.com/libnet/libnet)

These can be installed on Debian using the following commands:

```
sudo apt -y update \
  && sudo apt -y upgrade \
  && sudo apt -y install libcunit1 libcunit1-dev libpcap-dev libnet1 libnet1-dev
```

### Build and Run

Build `tapkit` using make:

```sh
make
```

Run `tapkit`:

```sh
./tapkit [tail|knock|emulate]
```

## Create a Testing Environment

To test `tapkit` we want a temporary Linux bridge and two TAP devices. Additionally, in an environment such a development container, `/dev/net/tun` most likely does not exist, so these instructions include commands to create this required character device.

```
sudo mkdir -p /dev/net
sudo mknod /dev/net/tun c 10 200
sudo chmod 600 /dev/net/tun

sudo ip link add br0 type bridge
sudo ip tuntap add tap0 mode tap
sudo ip link set dev tap0 up
sudo ip link set tap0 master br0
sudo ip tuntap add tap1 mode tap
sudo ip link set dev tap1 up
sudo ip link set tap1 master br0
```

## Misc. Information

Allow `tapkit` to send and receive raw network packets:

```
sudo setcap cap_net_raw,cap_net_admin=ep tapkit
```

https://linux.die.net/man/7/capabilities

#### `CAP_NET_RAW`

```
CAP_NET_RAW
    * Use RAW and PACKET sockets;
    * bind to any address for transparent proxying.
```

#### `CAP_NET_ADMIN`

```
CAP_NET_ADMIN
      Perform various network-related operations:
      * interface configuration;
      * administration of IP firewall, masquerading, and
        accounting;
      * modify routing tables;
      * bind to any address for transparent proxying;
      * set type-of-service (TOS);
      * clear driver statistics;
      * set promiscuous mode;
      * enabling multicasting;
      * use setsockopt(2) to set the following socket options:
        SO_DEBUG, SO_MARK, SO_PRIORITY (for a priority outside
        the range 0 to 6), SO_RCVBUFFORCE, and SO_SNDBUFFORCE.
```
