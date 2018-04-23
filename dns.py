#!/usr/local/bin/python3

import argparse
import socket
import sys
from enum import Enum
from contextlib import contextmanager


class Errors(Enum):
    """An Enum representing the types of errors that may occur."""
    SOCKET_ERROR = "Unable to open TCP socket connection to {}"
    HOSTNAME_ERROR = "Hostname ({}) could not be resolved."
    HTTPS_ERROR = "Could not could to HTTPS address {}"
    SEND_ERROR = "Could not send data to open TCP socket"


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


def main():
    """Main programmy thing, y'all know what it do"""
    parser = argparse.ArgumentParser(description="DNS Lookup Tool")

    parser.add_argument("hostname", type=str, action="store",
                        help="the hostname to lookup")

    args = parser.parse_args()


if __name__ == "__main__":
    main()
