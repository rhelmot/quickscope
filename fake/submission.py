#!/usr/bin/env python3

import os
import sys
import nclib

seen = set()

def status(sock, flag, stat):
    response = flag + b' ' + stat
    sock.sendln(response)
    sys.stdout.buffer.write(response + b'\n')
    sys.stdout.buffer.flush()

for sock in nclib.server.TCPServer(('0.0.0.0', 1337)):
    while True:
        line = sock.recvln().strip()
        if not line:
            break

        if line in seen:
            status(sock, line, b'DUP')
            continue

        for filename in os.listdir('flags'):
            with open(os.path.join('flags', filename), 'rb') as fp:
                flag = fp.read().strip()
            if flag == line:
                status(sock, line, b'OK')
                seen.add(line)
                break
        else:
            status(sock, line, b'INV')

    sock.close()
