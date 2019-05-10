#!/usr/bin/env python3

import sys
import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_address = ("localhost", 55555)
sock.bind(server_address)

while True:
    data, address = sock.recvfrom(8192)
    print(address, data)
