#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Simple LLDP (Low Level Discovery Protocol) frame capture/parse script,
    designed by Hao Feng (whisperaven@gmail.com).

    1, Just read the `device name` and `portid` and `vlanid` TLV, but
        you can add your own parser by using the return value of function
        `unpack_lldp_frame`.
    2, Because it uses `socket()` with some Linux Only socket flags, so
        it should be Only work under linux.
    3, No python 3 support in mind, just want to get the job done.

    Hope that someone find it useful, but WITHOUT ANY WARRANTY;
"""

import re
import sys
import signal

from ctypes import c_char, c_short, Structure
from fcntl import ioctl
from socket import socket, htons, inet_ntoa
from socket import AF_PACKET, AF_INET, SOCK_DGRAM, SOCK_RAW
from socket import gaierror

from struct import pack, unpack

## Magic constants from `/usr/include/linux/if_ether.h`:
ETH_P_ALL = 0x0003
ETH_ALEN = 6
ETH_HLEN = 14

## LLDP Ethernet Protocol:
# LLDP Length:
LLDP_TLV_TYPE_BIT_LEN = 7
LLDP_TLV_LEN_BIT_LEN = 9
LLDP_TLV_HEADER_LEN = 2         # 7 + 9 = 16
LLDP_TLV_OUI_LEN = 3
LLDP_TLV_SUBTYPE_LEN = 1
# LLDP Protocol BitFiddling Mask:
LLDP_TLV_TYPE_MASK = 0xfe00
LLDP_TLV_LEN_MASK = 0x1ff
# LLDP Protocol ID:
LLDP_PROTO_ID = 0x88cc
# LLDP TLV Type:
LLDP_TLV_TYPE_CHASSISID = 0x01
LLDP_TLV_TYPE_PORTID = 0x02
LLDP_TLV_DEVICE_NAME = 0x05
LLDP_PDUEND = 0x00
LLDP_TLV_ORGANIZATIONALLY_SPECIFIC = 0x7f
# LLDP TLV OUI Type:
LLDP_TLV_OUI_802_1 = 0x0008c2
LLDP_TLV_OUI_802_3 = 0x00120f

## Magic string for unpack packet:
UNPACK_ETH_HEADER_DEST = '!%s' % ('B' * ETH_ALEN)
UNPACK_ETH_HEADER_SRC = '!%s' % ('B' * ETH_ALEN)
UNPACK_ETH_HEADER_PROTO = '!H'

## Magic string for unpack LLDP packet:
UNPACK_LLDP_TLV_TYPE = '!H'
UNPACK_LLDP_TLV_OUI = '!%s' % ('B' * LLDP_TLV_OUI_LEN)
UNPACK_LLDP_TLV_SUBTYPE = '!B'

## Other info about network under linux:
NETDEV_INFO = '/proc/net/dev'
SIOCGIFADDR = 0x8915    # Socket opt for get ip addr under linux
SIOCSIFHWADDR = 0x8927  # Socket opt for get mac addr under linux
SIOCGIFFLAGS = 0x8913   # `G` for Get socket flags
SIOCSIFFLAGS = 0x8914   # `S` for Set socket flags
IFF_PROMISC = 0x100     # Enter Promiscuous mode


class ifreq(Structure):
    """ C-compatible `ifreq` struct """
    _fields_ = [("ifr_ifrn", c_char * 16),
                ("ifr_flags", c_short)]


def detect_netdevs():
    """ Get network interface name/ip, 
            ignore interface with no ip assigned """

    netdevs = list()
    netdev_regex = re.compile(r"""(.+?):[0-9]* .*$""")
    ip_gather_sock = socket(AF_INET, SOCK_DGRAM)

    fp = open(NETDEV_INFO, 'ro')
    for interface in fp:
        m = re.match(netdev_regex, interface)
        if m and 'lo' not in m.group(1):
            interface_name = m.group(1).strip()
            try:
                interface_ip = inet_ntoa(
                                    ioctl(ip_gather_sock.fileno(), SIOCGIFADDR, 
                                        pack('256s', interface_name[:15]))[20:24])
                netdevs.append((interface_name, interface_ip))
            except IOError: # There is no ip assigned to this device, ignore.
                continue

    return netdevs


def promiscuous_mode(interface, sock, enable=False):
    """ Enable/Disable NIC promiscuous mode via `ioctl` system call
            with c-compatible `ifreq` struct and `SIOC[G|S]IFFLAGS` """

    ifr = ifreq()
    ifr.ifr_ifrn = interface
    ioctl(sock.fileno(), SIOCGIFFLAGS, ifr)

    if enable:
        ifr.ifr_flags |= IFF_PROMISC
    else:
        ifr.ifr_flags &= ~IFF_PROMISC
    ioctl(sock.fileno(), SIOCSIFFLAGS, ifr)


def unpack_ethernet_frame(packet):
    """ Unpack ethernet frame """

    eth_header = packet[0:ETH_HLEN]
    eth_dest_mac = unpack(UNPACK_ETH_HEADER_DEST, eth_header[0:ETH_ALEN])
    eth_src_mac = unpack(UNPACK_ETH_HEADER_SRC, eth_header[ETH_ALEN:ETH_ALEN*2])
    eth_protocol = unpack(UNPACK_ETH_HEADER_PROTO, eth_header[ETH_ALEN*2:ETH_HLEN])[0]
    eth_payload = packet[ETH_HLEN:]

    return (eth_header, eth_dest_mac, eth_src_mac, eth_protocol, eth_payload)


def covert_hex_string(decimals):
    """ Covert decimals to hex string which start with `0x`, 
            and `strip` by `0x` """
    return [ hex(decimal).strip('0x').rjust(2, '0') for decimal in decimals ]


def unpack_lldp_frame(eth_payload):
    """ Unpack lldp frame """

    while eth_payload:

        tlv_header = unpack(UNPACK_LLDP_TLV_TYPE, eth_payload[:LLDP_TLV_HEADER_LEN])
        tlv_type = (tlv_header[0] & LLDP_TLV_TYPE_MASK) >> LLDP_TLV_LEN_BIT_LEN
        tlv_data_len = (tlv_header[0] & LLDP_TLV_LEN_MASK)
        tlv_payload = eth_payload[LLDP_TLV_HEADER_LEN:LLDP_TLV_HEADER_LEN + tlv_data_len]

        # These headers only available with 
        #   `LLDP_TLV_ORGANIZATIONALLY_SPECIFIC` TLV
        tlv_oui = None
        tlv_subtype = None

        if tlv_type == LLDP_TLV_ORGANIZATIONALLY_SPECIFIC:
            _tlv_oui = unpack(UNPACK_LLDP_TLV_OUI, tlv_payload[:LLDP_TLV_OUI_LEN])
            tlv_subtype = unpack(UNPACK_LLDP_TLV_SUBTYPE, 
                            tlv_payload[LLDP_TLV_OUI_LEN:LLDP_TLV_OUI_LEN + LLDP_TLV_SUBTYPE_LEN])[0]
            tlv_payload = tlv_payload[LLDP_TLV_OUI_LEN + LLDP_TLV_SUBTYPE_LEN:]
                
            # Covert oui from list to hex/decimals
            tlv_oui = str()
            for bit in _tlv_oui:
                tlv_oui += hex(bit).strip('0x').rjust(2, '0')
            tlv_oui = int(tlv_oui, 16)

        elif tlv_type == LLDP_PDUEND:
            break

        eth_payload = eth_payload[LLDP_TLV_HEADER_LEN + tlv_data_len:]

        yield (tlv_header, tlv_type, tlv_data_len, tlv_oui, \
                                        tlv_subtype, tlv_payload)
    

def exit_handler(signum, frame):
    """ Exit signal handler """

    capture_sock = frame.f_locals['capture_sock']
    interface_name = frame.f_locals['interface_name']

    promiscuous_mode(interface_name, capture_sock, False)
    print("Abort, %s eixt promiscuous mode." % interface_name)

    sys.exit(1)


def main():
    """ Low Level Discovery Protocol """

    max_capture_time = 45
    rv = dict()

    netdevs = detect_netdevs()
    capture_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))

    for interface_name, interface_ip in netdevs:

        promiscuous_mode(interface_name, capture_sock, True)
        rv[interface_name] = dict()

        signal.signal(signal.SIGINT, exit_handler)
        signal.signal(signal.SIGALRM, exit_handler)
        signal.alarm(max_capture_time)

        while True:

            packet = capture_sock.recvfrom(65565)
            packet = packet[0]
            eth_protocol, eth_payload = unpack_ethernet_frame(packet)[3:]

            if eth_protocol == LLDP_PROTO_ID:

                promiscuous_mode(interface_name, capture_sock, False)
                signal.signal(signal.SIGINT, signal.SIG_DFL)
                signal.signal(signal.SIGALRM, signal.SIG_DFL)
                signal.alarm(0)

                for tlv_parse_rv in unpack_lldp_frame(eth_payload):

                    tlv_header, tlv_type, tlv_data_len, tlv_oui, tlv_subtype, tlv_payload \
                                                                            = tlv_parse_rv

                    if tlv_type == LLDP_TLV_TYPE_PORTID:
                        rv[interface_name]['portid'] = re.sub(r'[\x00-\x08]', '', tlv_payload).strip()
                    elif tlv_type == LLDP_TLV_DEVICE_NAME:
                        rv[interface_name]['switch'] = tlv_payload
                    elif tlv_type == LLDP_TLV_ORGANIZATIONALLY_SPECIFIC:
                        if tlv_oui == LLDP_TLV_OUI_802_1 and tlv_subtype == 3:
                            rv[interface_name]['vlan'] = re.sub(r'[\x00-\x08]', '', tlv_payload).strip()

                break

    print(rv)

# Start:
if __name__ == '__main__':
    main()
