#!/usr/bin/env python3

# TODO alert for sketchy behaviors
#      - md5 matches known bad hash
#      - no file on disk
#      - executed from non trusted directory (tmp,, dev/shm, ...  or not /bin..)
#      - command line is bash -c or python -c
#      - cli is base64'd
#      - a user who has never executed a file, executes a file.
# TODO log to disk
# TODO splunk or elk?
# TODO if server has never seen a file, retrieve it from client somehow
# TODO if file is packed, is golang, is compiled python, ...
# TODO if suid binary is executed
# TODO if sketchy shit is in the environment (nopsleds, environments dont match previous environment, ..)
# TODO run yara against unknown bins
# TODO entropy of file?? not sure if this is a good metric, but if entropy is high, chances are its crypted.
# TODO alert on weird cwd
# TODO md5 changed
# TODO watchlist for hashes/process names

import sys
import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_address = ("localhost", 55555)
sock.bind(server_address)

while True:
    data, address = sock.recvfrom(8192)
    print(address, data)
