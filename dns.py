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


class DNSAnswer(object):

    SKIP_BYTES = 12

    @staticmethod
    def handle_ip4(packet, start):
        length = DNSAnswer.read_length(packet, start)
        start = start + DNSAnswer.SKIP_BYTES

        ip = packet[start: start + length]
        return ".".join([str(x) for x in ip])

    @staticmethod
    def handle_ip6(packet, start):
        length = DNSAnswer.read_length(packet, start)
        start = start + DNSAnswer.SKIP_BYTES

        ip = packet[start: start + length]
        result = ""
        for i, num in enumerate(ip):
            result += format(num, '02x')
            if i % 2 != 0:
                result += ":"
        return result[:-1]

    @staticmethod
    def handle_mx(packet, start):
        start = start + DNSAnswer.SKIP_BYTES
        preference = packet[start+1]

        server = DNSAnswer._handle_mx(packet, start+2)
        return ".".join(server)

    @staticmethod
    def _handle_mx(packet, start):
        current = start + 1
        length = packet[start]

        sections = []

        while length != 0 and length != 192:
            sections.append(packet[current:current+length].decode('ISO-8859-1'))
            current, length = current+length+1, packet[current+length]

        if length == 192:
            follow = DNSAnswer._handle_mx(packet, packet[current])
            sections.extend(follow)

        return sections


    @staticmethod
    def handle_cname(packet, start):
        start = start + DNSAnswer.SKIP_BYTES

        server = DNSAnswer._handle_mx(packet, start)
        return ".".join(server)

    @staticmethod
    def handle_txt(packet, start):
        length = DNSAnswer.read_length(packet, start)
        start = start + DNSAnswer.SKIP_BYTES
        return packet[start:start+length].decode('ISO-8859-1')

    @staticmethod
    def read_length(packet, start):
        return packet[start + DNSAnswer.SKIP_BYTES - 1]


HANDLERS = {
    DomainType.A: DNSAnswer.handle_ip4,
    DomainType.AAAA: DNSAnswer.handle_ip6,
    DomainType.MX: DNSAnswer.handle_mx,
    DomainType.CNAME: DNSAnswer.handle_cname,
    DomainType.TXT: DNSAnswer.handle_txt,
    DomainType.PTR: DNSAnswer.handle_cname
}


class DNSReader(object):
    def __init__(self, hostname, dns=DNS_SERVER, reverse=False):
        if reverse:
            hostname = ".".join(hostname.split(".")[::-1])
            hostname = hostname + ".in-addr.arpa"

        self.hostname = hostname
        self.dns = dns
        self.reverse = reverse
        self.id = [random.randint(0, 255), random.randint(0, 255)]
        self.header = self.id + [1, 0, 0, 1, 0, 0, 0, 0, 0, 0]
        self.queries = []

    def add_query(self, type):
        if self.reverse and type != DomainType.PTR:
            log_error(Errors.NON_PTR)
        self.queries.append(self._generate_query(type))

    @property
    def requests(self):
        for query in self.queries:
            yield bytes(self.header + query)

    @property
    def answers(self):
        answers = {}

        for response in self.query(self.dns):
            for type, answer in self.scan(response):
                answer_item = answers.get(type, set())
                answers[type] = answer_item.union([answer])

        return answers

    def query(self, dns_server=DNS_SERVER):
        with open_socket(dns_server, 53) as socket:
            for request in self.requests:
                socket.sendall(request)
                reply = socket.recv(4096)

                yield bytearray(reply)

    def scan(self, response):
        if self.id != [response[0], response[1]]:
            log_error(Errors.DNS_ID_ERROR)

        options = convert_binary(response[2])
        options += convert_binary(response[3])

        if options[0] != 1:
            log_error(Errors.NON_RESPONSE_ERROR)

        query_count = response[5]
        answer_count = response[7]
        authority_count = response[9]
        additional_count = response[11]

        start = 16 + len(self._encode_hostname(self.hostname))
        offset = start
        for answer in range(answer_count):
            length = DNSAnswer.read_length(response, offset)
            yield self.scan_answer(response, offset)
            offset += length + 12

    def scan_answer(self, response, start):
        type = DomainType(response[start + 3])

        handler = HANDLERS.get(type, lambda x, y: None)
        result = handler(response, start)

        return type, result

    def _generate_query(self, type):
        query = self._encode_hostname(self.hostname)
        query.extend([0, type.value])
        query.extend([0, 1])
        return query

    @staticmethod
    def _encode_hostname(hostname):
        parts = hostname.split(".")

        bytes = []
        for part in parts:
            bytes.append(len(part))
            for letter in part:
                bytes.append(ord(letter))
        bytes.append(0)

        return bytes


class Errors(Enum):
    """An Enum representing the types of errors that may occur."""
    SOCKET_ERROR = "Unable to open TCP socket connection to {}"
    HOSTNAME_ERROR = "Hostname ({}) could not be resolved."
    HTTPS_ERROR = "Could not could to HTTPS address {}"
    SEND_ERROR = "Could not send data to open TCP socket"
    DNS_ID_ERROR = "DNS ID of response packet does not match request packet"
    NON_RESPONSE_ERROR = "Attempted to read a non-response packet"
    NON_PTR = "Attempted to add a non-pointer request to reverse lookup"


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

    packet = DNSReader(args.hostname, dns=args.dns, reverse=args.reverse)

    if args.reverse:
        packet.add_query(DomainType.PTR)
    else:
        packet.add_query(DomainType.A)
        packet.add_query(DomainType.AAAA)
        packet.add_query(DomainType.MX)
        packet.add_query(DomainType.CNAME)
        packet.add_query(DomainType.TXT)

    answers = packet.answers

    for type, answers in answers.items():
        print(type)
        for answer in answers:
            print(answer)
        print()


if __name__ == "__main__":
    main()
