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

```
sudo mkdir -p /dev/net
sudo mknod /dev/net/tun c 10 200
sudo chmod 600 /dev/net/tun

sudo ip link add br0 type bridge
sudo ip tuntap add tap0 mode tap
sudo ip link set dev tap0 up
sudo ip link set tap0 master br0
```

## OVS Commands

```
sudo ovs-vsctl add-br br0
sudo ip tuntap add mode tap vnet0
sudo ip link set vnet0 up
sudo ovs-vsctl add-port br0 vnet0
```

## Misc. Information

Allow `tapkit` to receive raw network packets,

```
sudo setcap cap_net_raw=ep tapkit
```

### `CAP_NET_RAW`

```
https://linux.die.net/man/7/capabilities

CAP_NET_RAW
    *

    use RAW and PACKET sockets;

    *

    bind to any address for transparent proxying.
```
