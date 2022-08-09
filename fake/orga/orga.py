#!/usr/bin/env python3
# pylint: disable=bare-except,global-statement

from typing import Set, List, Dict, Tuple
import string
import sys
import random
import json
import time
import threading
import nclib
import traceback

# serves flag submission on port 1337
# serves game status on port 1338
# reads team list (pod:localip) from argv[1]
# reads service list (name:port) from argv[2]

Service = str
Team = str
Flag = bytes
FlagID = str
Port = int

TICK = 0
TICK_LENGTH = 60
GRACE_TICKS = 2

TEAMS: List[Team] = []
SERVICES: List[Tuple[Service, Port]] = []

def update_globals():
    global TEAMS, SERVICES
    with open(sys.argv[1], 'r', encoding='utf-8') as fp:
        TEAMS = [(line.split(':')[1], line.split(':')[2].strip()) for line in fp]
    with open(sys.argv[2], 'r', encoding='utf-8') as fp:
        SERVICES = [(line.split(':')[0], int(line.split(':')[1])) for line in fp]

update_globals()

ALL_FLAGS: Set[Flag] = set()
SUBMITTED_FLAGS: Set[Flag] = set()
TICK_FLAGS: List[Set[Flag]] = []
TICK_FLAG_IDS: List[Dict[Service, Dict[Team, FlagID]]] = []

def sub_status(sock, flag, stat):
    response = flag + b' ' + stat
    sock.sendln(response)
    sys.stdout.buffer.write(response + b'\n')
    sys.stdout.buffer.flush()


def submission_routine():
    for sock in nclib.server.TCPServer(('0.0.0.0', 1337)):
        threading.Thread(target=submission_client_routine, args=(sock,)).start()

def submission_client_routine(sock):
    while True:
        line = sock.recvln().strip()
        if not line:
            break

        if line in SUBMITTED_FLAGS:
            sub_status(sock, line, b'DUP')
        elif any(line in flagset for flagset in TICK_FLAGS[max(0, TICK-GRACE_TICKS):TICK+1]):
            sub_status(sock, line, b'OK')
            SUBMITTED_FLAGS.add(line)
        elif line in ALL_FLAGS:
            sub_status(sock, line, b'OLD')
        else:
            sub_status(sock, line, b'INV')

    sock.close()

def game_status_routine():
    for sock in nclib.server.TCPServer(('0.0.0.0', 1338)):
        tick = TICK
        sock.write(json.dumps({
            "tick": tick,
            "services": TICK_FLAG_IDS[tick]
        }).encode())
        sock.close()

FLAG_CHARS = string.ascii_letters + string.digits
def gen_flag():
    return ('FLG' + ''.join(random.choice(FLAG_CHARS) for _ in range(8))).encode()
def gen_flagid():
    return 'FLGID_' + str(random.randrange(0, 1000000000))

def setflag(host, port, flag_id, flag):
    sock = nclib.Netcat((host, port))
    sock.sendln(b'PUT')
    sock.sendln(flag_id)
    sock.sendln(flag)
    sock.close()

def create_tick():
    update_globals()
    tick = len(TICK_FLAGS)
    tick_flags = set()
    tick_flag_ids = {}

    for service, port in SERVICES:
        service_data = {}
        for pod, ip in TEAMS:
            flag_id = gen_flagid()
            flag = gen_flag()
            try:
                setflag(pod, port, flag_id, flag)
            except:
                traceback.print_exc()
            else:
                service_data[ip] = flag_id
                tick_flags.add(flag)

        tick_flag_ids[service] = service_data

    TICK_FLAGS.append(tick_flags)
    ALL_FLAGS.update(tick_flags)
    TICK_FLAG_IDS.append(tick_flag_ids)
    return tick

def main():
    global TICK
    next_tick = create_tick()
    assert next_tick == TICK == 0

    threading.Thread(target=submission_routine).start()
    threading.Thread(target=game_status_routine).start()

    boot_time = time.time()

    while True:
        tick_starts_at = boot_time + TICK_LENGTH * next_tick
        sleepy = tick_starts_at - time.time()
        if sleepy > 0:
            time.sleep(sleepy)
        TICK = next_tick

        next_tick = create_tick()

if __name__ == "__main__":
    main()
