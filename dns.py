#!/usr/local/bin/python3

import argparse
import socket
import sys
from enum import Enum
from contextlib import contextmanager
import random

DNS_SERVER = "8.8.8.8"


class DomainType(Enum):
    A = 1
    CNAME = 5
    NULL = 10
    PTR = 12
    MX = 15
    TXT = 16
    AAAA = 28


class DNSRequest(object):
    def __init__(self, type=DomainType.A):
        self._id = [random.randint(0, 255), random.randint(0, 255)]

        self._check_disabled = [1, 0]
        self._query_count = [0, 1]
        self._answer_count = [0, 0]
        self._authority_record_count = [0, 0]
        self._additional_record_count = [0, 0]

        self._query_type = [0, type.value]
        self._query_class = [0, 1]

    def get_header(self):
        return self._id + self._check_disabled + self._query_count \
               + self._answer_count + self._authority_record_count \
               + self._additional_record_count

    def get_tail(self):
        return self._query_type + self._query_class


class Errors(Enum):
    """An Enum representing the types of errors that may occur."""
    SOCKET_ERROR = "Unable to open TCP socket connection to {}"
    HOSTNAME_ERROR = "Hostname ({}) could not be resolved."
    HTTPS_ERROR = "Could not could to HTTPS address {}"
    SEND_ERROR = "Could not send data to open TCP socket"
    DNS_ID_ERROR = "DNS ID of response packet does not match request packet"
    NON_RESPONSE_ERROR = "Attempted to read a non-response packet"


def log_error(error, *parameters):
    """
    Log that an error has occurred and exit the program.

    Args:
        error (Errors): The type of error that has occurred.
        *parameters (*): Any extra information relevant to the error.
    """
    print(error.name, ":", error.value.format(*parameters))
    sys.exit(1)


@contextmanager
def open_socket(ip, port=80):
    """
    Open a socket to an IP Address and a port.
    Automatically close connection using a context manager.

    Args:
        ip (str): The IP address with which a connection is opened.
        port (int): The port with which a connection is opened.

    Yields:
        (socket.socket): A socket connection to the given IP address.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect((ip, port))
        yield sock
        sock.close()
    except socket.error:
        log_error(Errors.SOCKET_ERROR, ip)


def convert_binary(number, length=8):
    return [int(x) for x in '{0:0{1}b}'.format(number, length)]


def encode_hostname(hostname):
    parts = hostname.split(".")

    bytes = []

    for part in parts:
        bytes.append(len(part))
        for letter in part:
            bytes.append(ord(letter))
    bytes.append(0)

    return bytes


def encode_hex(hex_code):
    data = []

    hex_code = hex_code.replace("\n", " ")
    for bite in hex_code.split(" "):
        bite = bite.strip()
        data.append(int(bite, 16))

    return data


def decode_ip(ip):
    return ".".join([str(x) for x in ip])


def decode_ip6(ip):
    result = ""
    for i, num in enumerate(ip):
        result += format(num, '02x')
        if i % 2 != 0:
            result += ":"
    return result[:-1]


def decode_email(ip, whole, host_start=0, hostname=""):
    priority = int.from_bytes(ip[0:2], byteorder='big', signed=False)
    start = 2

    sections = []
    while start != 0:
        if start >= len(ip):
            print('exceeded')
            # print(".".join(sections))
            return sections
        length = ip[start]

        if length == 192:
            starting = ip[start+1]-7

            if ip[start+1] == host_start:
                return sections + [hostname]

            sections.extend(decode_email(whole[starting:], whole,
                                         host_start=host_start,
                                         hostname=hostname)[1:])
            break
        if length == 0:
            print("found zero")
            return sections
        subsection = ip[start+1:start+length+1]

        section = "".join([format(x, '02x') + " " for x in subsection])
        section = bytearray.fromhex(section).decode('ISO-8859-1')

        sections.append(section)
        start = start+length+1

    return sections


def decode_txt(ip):
    length = ip[0]
    return ip[1:length].decode('ISO-8859-1')


def decode_cname(ip, whole):
    length = ip[0]
    current = 1
    sections = []

    while length != 0 and length != 192:
        sections.append(ip[current:current+length].decode('ISO-8859-1'))
        current, length = current+length+1, ip[current+length]

    if length == 192:
        sections.append(decode_cname(whole[ip[current]:], whole))

    return ".".join(sections)


def read_answer(bytes, whole, host_start=0, hostname=""):

    length = bytes[11]

    type = DomainType(bytes[3])

    bytes = bytes[12:12+length]

    if type == DomainType.A:
        ip = decode_ip(bytes)
    elif type == DomainType.AAAA:
        ip = decode_ip6(bytes)
    elif type == DomainType.MX:
        ip = ".".join(decode_email(bytes, whole, host_start=host_start,
                                   hostname=hostname))
    elif type == DomainType.TXT:
        ip = decode_txt(bytes)
    elif type == DomainType.CNAME:
        ip = decode_cname(bytes, whole)
    elif type ==DomainType.PTR:
        ip = decode_cname(bytes, whole)
    else:
        ip = ""

    return ip, length + 12, type


def build_packet(hostname, dns_type=DomainType.A):
    request = DNSRequest(type=dns_type)

    data = request.get_header()
    data += encode_hostname(hostname)
    data += request.get_tail()

    return bytes(data)


def dns_lookup(hostname, dns_server=DNS_SERVER, dns_type=DomainType.A):
    """
    Use a UDP socket connection to dns_server to retrieve
    information about the hostname.

    Parameters:
        hostname (str): The hostname to lookup
        dns_server (str): The DNS server to connect to
        dns_type (DomainType): The type of DNS request to make.

    Returns:
        (str): The IP Address of the hostname
    """
    request = DNSRequest(type=dns_type)

    data = request.get_header()
    data += encode_hostname(hostname)
    data += request.get_tail()

    ips = {domain: [] for domain in DomainType}

    with open_socket(dns_server, 53) as socket:
        socket.sendall(bytes(data))
        reply = socket.recv(4096)

        answers = bytearray(reply)[7]

        if answers == 0:
            return None

        start = 18 + len(hostname)

        for i in range(answers):
            ip, offset, type = read_answer(bytearray(reply)[start:], bytearray(reply),
                                           host_start=len(request.get_header()),
                                           hostname=hostname)
            start += offset
            ips[type].append(ip)

        return ips


def main():
    """Main programmy thing, y'all know what it do"""
    parser = argparse.ArgumentParser(description="DNS Lookup Tool")

    parser.add_argument("hostname", type=str, action="store",
                        help="the hostname to lookup")
    parser.add_argument("-d", "--dns-server", dest="dns", default=DNS_SERVER,
                        help="the dns server to use to lookup the hostname")
    parser.add_argument("-r", "--reverse", dest="reverse", action="store_true",
                        help="perform a reverse lookup")

    args = parser.parse_args()

    types = {
        "IPv4": DomainType.A,
        "IPv6": DomainType.AAAA,
        "MX": DomainType.MX,
        "TXT": DomainType.TXT,
        "CNAME": DomainType.CNAME
    }

    if args.reverse:
        hostname = ".".join(args.hostname.split(".")[::-1])
        records = dns_lookup(hostname + ".in-addr.arpa", dns_server=args.dns,
                             dns_type=DomainType.PTR)
        if records is None or len(records.get(DomainType.PTR)) == 0:
            print(f"No Records Found")
        else:
            print(f"{', '.join(records.get(DomainType.PTR))}")
        return

    for name, type in types.items():
        records = dns_lookup(args.hostname, dns_server=args.dns, dns_type=type)
        if records is None or len(records.get(type)) == 0:
            print(f"{name}: No Records Found")
        else:
            print(f"{name}: {', '.join(records.get(type))}")
        print()


if __name__ == "__main__":
    main()
