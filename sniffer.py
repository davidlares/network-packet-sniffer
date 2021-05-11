from base64 import b64decode
from scapy.all import *
import argparse

# TCP connections
def handle_tcp(packet):
    # tcp ports
    interesting_tcp_ports = {21: 'ftp', 23: 'telnet', 25: 'smtp', 80: 'http'}
    app = None
    # source port
    sport = packet[TCP].sport
    # destination port
    dport = packet[TCP].dport
    # dictionary protocol comparison
    if sport in interesting_tcp_ports:
        app = interesting_tcp_ports[sport]
        server_addr = packet[IP].src
    elif dport in interesting_tcp_ports:
        app = interesting_tcp_ports[dport]
        server_addr = packet[IP].src
    print('Handling packet proto=TCP, sport={}, dport={}'.format(sport, dport))
    # generic TCP packet
    if not app:
        print('Handling TCP packet')
        print(packet.summary())
    # calling proper function
    else:
        handle_function = globals()['handle_{}'.format(app)]
        handle_function(packet, server_addr)

# UDP connections
def handle_udp(packet):
    # udp ports
    interesting_udp_ports = {53: 'dns', 161: 'snmp', 389: 'ldap'}
    app = None
    # source port
    sport = packet[UDP].sport
    # destination prot
    dport = packet[UDP].dport
    # dictionary protocol comparison
    if sport in interesting_udp_ports:
        app = interesting_udp_ports[sport]
    elif dport in interesting_udp_ports:
        app = interesting_udp_ports[dport]
    print('Handling packet proto=UDP, sport={}, dport={}'.format(sport, dport))
    # generic UDP packet
    if not app:
        print('Handling UDP packet')
        print(packet.summary())
    # calling proper function
    else:
        handle_function = globals()['handle_{}'.format(app)]
        handle_function(packet)

# can be also for icmp, ftp, dns, http, smtp, telnet, ldap
def handle_http(packet, server_addr):
    print('Handling HTTP packet')
    http_host = None
    basic_auth = None
    other_auth = None
    # handling packets
    if Raw in packet:
        http_content = packet[Raw].load.decode().splitlines() # deconstructing
        for line in http_content:
            if re.search(r'^Host:', line):
                http_host = line.split()[-1]
            # finding basic authentication
            elif re.search(r'^Authorization:', line):
                if re.search(r'^Authorization: Basic', line):
                    basic_auth = line.split()[-1]
            # set to 'other auth'
                else:
                    other_auth = line
            # checking host
            if http_host and (basic_auth or other_auth):
                break

    # handling basic auth strategies ()
    if basic_auth:
        tmp = b64decode(basic_auth).decode().split(':') # decoding values
        username = tmp[0]
        password = tmp[1]
        print('Captured HTTP basic auth credentials! server={}, hostname={}, username={}, password={}'.format(server_addr,http_host,username,password))

    # handling other type of authentication
    if other_auth:
        print('Captured HTTP auth credentials! server={}, hostname={}, creds_string="{}"'.format(server_addr, http_host, other_auth))

def handle_icmp(packet, server_addr):
    print('Handling ICMP packet')
    print(packet.summary())


def handle_ftp(packet, server_addr):
    print('Handling FTP packet')
    print(packet.summary())


def handle_dns(packet):
    print('Handling DNS packet')
    print(packet.summary())

def handle_smtp(packet, server_addr):
    print('Handling SMTP packet')
    print(packet.summary())


def handle_snmp(packet, server_addr):
    print('Handling SNMP packet')
    print(packet.summary())

def handle_telnet(packet, server_addr):
    print('Handling Telnet packet')
    print(packet.summary())


def handle_ldap(packet, server_addr):
    print('Handling LDAP packet')
    print(packet.summary())


def handle_packet(packet):
    proto_table = {1: 'icmp', 6: 'tcp', 17: 'udp'}
    if IP not in packet:
        return
    proto = proto_table[packet[IP].proto]
    handle_function = globals()['handle_{}'.format(proto)]
    print('...')
    handle_function(packet)


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='A general-purpose network packet sniffer.')
    parser.add_argument('-f', '--filter', help='Set a filter to capture specific packets')
    parser.add_argument('-i', '--iface', required=True, help='Listen on the specified interface')
    args = parser.parse_args()
    kwargs = {'prn': handle_packet, 'store': False}
    if args.filter:
        kwargs['filter'] = args.filter
    if args.iface:
        kwargs['iface'] = args.iface
    sniff(**kwargs)
