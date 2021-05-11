# Network packet sniffer

Many tools can perform passive and active network active packets. These ones analyze all the network packets regardless of the destination that obviously hits a network interface of your computer.

The network packets are received from a network interface, which reads the packet to find out its destination. if the destination does not match the interface, the packet will be tossed away. This is the default behavior of network interfaces but with it's possible to capture ALL packets, this is done with the promiscuous mode. Of course, this does not apply to every NIC.

The promiscuous mode allows doing deep packet inspection to look for valuable information or unusual patterns in network packets.

This script with the help of the `Scapy library`, which analyzes non-encrypted `TCP` and `UDP` protocols and deconstruct packets components based on the network captured from a network interface. This also handles HTTP authentication mechanisms and even the decoding process of credentials.

## Unencrypted protocols

These are basically the ones that do not contain any data encryption.

We can list: `ftp`, `telnet`, `smtp`, `http` for the `TCP's`. And `dns`, `snmp`, and `ldap` for the `UDP's`.

## How to use it

It requires an `iface` and an optional `filter` for specific protocol.

You can run it like this: `python sniffer.py -i eth0 -f http`

The `-i` is for addressing a network interface, and the `-f` is for filtering protocols.

## Requirements

Make sure you have a complete `virtualenv` set up, with the dependencies installed.

Install them with: `pip install -r requirements.txt`

## Credits

 - [David E Lares](https://twitter.com/davidlares3)

## License

 - [MIT](https://opensource.org/licenses/MIT)
