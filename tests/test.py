from typing import Optional, List
import subprocess
import nclib
import time
import unittest
import quickscope
from quickscope.common import *
import random
import threading
import concurrent.futures
from pathlib import Path

BASE_DIR = Path(__file__).absolute().parent

kind_str = {
        SubmissionResult.OK: "O",
        SubmissionResult.INVALID: "I",
        SubmissionResult.UNKNOWN: "U",
        SubmissionResult.TOO_OLD: "T",
        SubmissionResult.SELF: "S",
        SubmissionResult.ALREADY_SUBMITTED: "A",
}

str_kind = {b: a for a, b in kind_str.items()}

def gen_flag(kind: SubmissionResult, num: Optional[int] = None) -> bytes:
    if num is None:
        num = random.randrange(10**10)
    result = f'FLAG{kind_str[kind]}{num:010d}'.encode()
    assert len(result) == 15
    return result

class MyTracker(quickscope.tracker.Tracker):
    def __init__(self):
        super().__init__()
        self.next_game_status = GameStatus(1, [])
        self.log_by_flag = {}

    FLAG_REGEX = b'FLAG[OIUTSA][0-9]{10}'

    def submit_flags(self, flags):
        result = []
        for submission in flags:
            status = str_kind[chr(submission.flag[4])]
            log = SubmissionLog(submission, status)
            result.append(log)
            self.log_by_flag[submission.flag] = log
        return result

    def get_status(self):
        return self.next_game_status

    def instrument_targets(self, targets):
        return targets

    def perform_tick(self, targets: List[Target]):
        self.next_game_status = GameStatus(self.next_game_status.tick + 1, targets)
        self.ingest_status(self.get_status())

    def run_until(self, port, predicate, timeout):
        #scraper_thread = threading.Thread(target=self.scraper_thread)
        #scraper_thread.start()

        server = nclib.server.TCPServer((self.BIND_TO, port))
        timed_out = False

        def wait():
            nonlocal timed_out
            for _ in range(10):
                time.sleep(timeout / 10)
                if predicate():
                    server.close()
                    return
            timed_out = True
            server.close()
        threading.Thread(target=wait).start()

        with concurrent.futures.ThreadPoolExecutor(self.WORKER_THREADS) as executor:
            for client in server:
                executor.submit(self.handle, client)

        if timed_out:
            raise TimeoutError("Failed to reach predicate")

class Tests(unittest.TestCase):
    def test_basic(self):
        tracker = MyTracker()

        team = Team("test_team", "hostname")
        service = Service("test_svc", 1234)
        flag = gen_flag(SubmissionResult.OK)
        tracker.perform_tick([Target(team, service, flag.decode())])
        port = random.randrange(0x2000, 0x8000)
        with subprocess.Popen(['quickscope', '--server', f'localhost:{port}', '--script', BASE_DIR / 'script_basic.py', '--everyone']):
            tracker.run_until(port, lambda: flag in tracker.log_by_flag, 4)
            assert tracker.log_by_flag[flag].result == SubmissionResult.OK

