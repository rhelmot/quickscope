#!/usr/bin/env python3

import sys
import random
import nclib

store = {}

PORT = int(sys.argv[1])
PATCH_DIFFICULTY = float(sys.argv[2])

for sock in nclib.server.TCPServer(('0.0.0.0', PORT)):
    line = sock.recvln().strip()
    if line == b'GET':
        flag_id = sock.recvln().strip()
        confidence = float(sock.recvln().strip())
        if flag_id in store:
            if confidence - PATCH_DIFFICULTY >= random.uniform(0, 1):
                sock.sendln(store[flag_id])
            else:
                sock.sendln(b'exploit failed')
        else:
            sock.sendln(b'no such flag id')

    elif line == b'PUT':
        flag_id = sock.recvln().strip()
        flag = sock.recvln().strip()
        store[flag_id] = flag

    sock.close()
