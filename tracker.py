from typing import List, Tuple, Dict
import sys
import argparse
import enum
import json
import concurrent.futures
import threading
import nclib
import time
from dataclasses import dataclass, field
from collections import defaultdict

PORT = 3356

@dataclass(frozen=True)
class Target:
    host: str
    port: int
    flag_id: str

    def __str__(self):
        return '%s %d %s' % (self.host, self.port, self.flag_id)

    def same_service(self, other: 'Target'):
        return self.host == other.host and self.port == other.port

    @classmethod
    def parse(cls, line: str) -> 'Target':
        thingy = json.loads(line)
        return cls(
            host=thingy['host'],
            port=thingy['port'],
            flag_id=thingy['flag_id'],
        )

    def dump(self) -> str:
        return json.dumps({
            'host': self.host,
            'port': self.port,
            'flag_id': self.flag_id,
        })

@dataclass(frozen=True)
class NamedTarget:
    """
    Generally only used for communication inside the tracker
    (i.e. when scraping the active services)
    """
    target: Target
    name: str

class SubmissionResult(enum.Enum):
    OK = 'OK'
    INVALID = 'INVALID'
    UNKNOWN = 'UNKNOWN'
    TOO_OLD = 'TOO_OLD'
    SELF = 'SELF'
    ALREADY_SUBMITTED = 'ALREADY_SUBMITTED'

@dataclass
class Submission:
    flag: bytes
    target: Target
    script: str

    @classmethod
    def parse(cls, line: str) -> 'Submission':
        thingy = json.loads(line)
        return cls(
            flag=thingy['flag'].encode('latin-1'),
            target=Target(
                host=thingy['host'],
                port=thingy['port'],
                flag_id=thingy['flag_id']),
            script=thingy['script']
        )

    def dump(self) -> str:
        return json.dumps({
            'flag': self.flag.decode('latin-1'),
            'host': self.target.host,
            'port': self.target.port,
            'flag_id': self.target.flag_id,
            'script': self.script,
        })

@dataclass
class SubmissionLog:
    submission: Submission
    result: SubmissionResult

@dataclass
class ScriptStatus:
    runs: int = 0

@dataclass
class TargetStatus:
    tick_last_seen: int
    script_status: Dict[str, ScriptStatus] = field(default_factory=lambda: defaultdict(ScriptStatus))
    retired: bool = False

@dataclass
class GameStatus:
    tick: int
    targets: List[NamedTarget]

class Tracker:
    # HERE'S WHAT YOU IMPLEMENT
    FLAG_REGEX: bytes = NotImplemented

    def get_status(self) -> GameStatus:
        raise NotImplementedError

    def submit_flags(self, flags: List[Submission]) -> List[SubmissionLog]:
        raise NotImplementedError

    TICK_TIMEOUT = 3
    RETRY_TIMEOUT = 3

    # DON'T TOUCH THIS

    @classmethod
    def main(cls):
        parser = argparse.ArgumentParser("The tracker")
        parser.add_argument("workers", type=int)
        parser.add_argument("bindto", type=str)
        args = parser.parse_args(sys.argv[1:])

        cls(args.workers, args.bindto).run()

    def __init__(self, workers: int, bindto: str):
        self.workers = workers
        self.bindto = bindto

        self.lock = threading.Lock()
        self.targets: Dict[Target, TargetStatus] = {}
        self.names: Dict[str, Target] = {}

        assert b'\n' not in self.FLAG_REGEX

    def run(self):
        server = nclib.server.TCPServer((self.bindto, PORT))
        scraper_thread = threading.Thread(target=self.scraper_thread)
        scraper_thread.start()
        with concurrent.futures.ThreadPoolExecutor(self.workers) as executor:
            for client in server:
                executor.submit(self.handle, client)

    def handle(self, sock: nclib.Netcat):
        line = sock.readln(max_size=100, timeout=1).strip()
        if line == b'submit':
            self.serve_submit(sock)
        elif line == b'gettargets':
            self.serve_gettargets(sock)
        elif line == b'getstatus':
            self.serve_getstatus(sock)
        sock.close()

    def serve_submit(self, sock: nclib.Netcat):
        lines = sock.recvall(timeout=1)
        submissions = []
        for line in lines.splitlines():
            try:
                line = line.decode()
                submission = Submission.parse(line)
                submissions.append(submission)

            except Exception as e:
                print('Exception during submit: %s' % repr(e))

        try:
            results = self.submit_flags(submissions)
        except Exception as e:
            print('Exception during submit: %s' % repr(e))
            return

        for result in results:
            if result.result == SubmissionResult.SELF:
                self.untarget_host_port(result.submission.target.host, result.submission.target.port)
            elif result.result in SubmissionResult.OK:
                print('BREAD')
                self.untarget_target(result.submission.target)
            elif result.result == SubmissionResult.ALREADY_SUBMITTED:
                self.untarget_target(result.submission.target)
            elif result.result == SubmissionResult.INVALID:
                print('Warning: getting bogus flags for', result.submission.target)
                pass
            elif result.result == SubmissionResult.UNKNOWN:
                pass
            elif result.result == SubmissionResult.TOO_OLD:
                pass
            else:
                print("Bad submission result:", result.result, "(is your submitter misbehaving?)")

    def serve_gettargets(self, sock: nclib.Netcat):
        script = sock.readln(max_size=100, timeout=1).strip().decode()
        name = sock.readln(max_size=100, timeout=1).strip().decode()
        sock.sendln(self.FLAG_REGEX)
        targets = self.get_targets_for_script(script, name)
        for target in targets:
            sock.sendln(target.dump().encode())

    def serve_getstatus(self, sock: nclib.Netcat):
        sock.sendln(b'TODO')
        breakpoint()

    def scraper_thread(self):
        old_tick = None
        while True:
            try:
                status = self.get_status()
            except Exception as e:
                print('Error getting status: %s' % repr(e))
                time.sleep(10)
                continue

            if status.tick == old_tick:
                time.sleep(10)
                continue
            old_tick = status.tick
            self.ingest_status(status)

    def ingest_status(self, gamestatus: GameStatus):
        with self.lock:
            for target in gamestatus.targets:
                self.names[target.name] = target.target

                if target.target in self.targets:
                    self.targets[target.target].tick_last_seen = gamestatus.tick
                else:
                    self.targets[target.target] = TargetStatus(tick_last_seen=gamestatus.tick)

            to_remove = []
            for target, status in self.targets.items():
                if status.tick_last_seen < gamestatus.tick - self.TICK_TIMEOUT:
                    to_remove.append(target)
            for target in to_remove:
                self.targets.pop(target)

    def untarget_host_port(self, host: str, port: int):
        with self.lock:
            for target, status in self.targets.items():
                if target.host == host and target.port == port:
                    status.retired = True

    def untarget_target(self, target: Target):
        try:
            self.targets[target].retired = True
        except KeyError:
            pass

    def get_targets_for_script(self, script, target_name) -> List[Target]:
        results = []
        if target_name not in self.names:
            print('Warning: someone requested unknown service', target_name)
            return results

        with self.lock:
            for target, status in self.targets.items():
                if not target.same_service(self.names[target_name]):
                    continue
                if status.retired:
                    continue
                if status.script_status[script].runs >= self.RETRY_TIMEOUT:
                    continue
                status.script_status[script].runs += 1
                results.append(target)

        return results
