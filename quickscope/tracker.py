import random
import traceback
import concurrent.futures
import threading
import nclib
import time

from .common import *

class Tracker:
    # HERE'S WHAT YOU IMPLEMENT
    FLAG_REGEX: bytes = NotImplemented

    def get_status(self) -> GameStatus:
        raise NotImplementedError

    def submit_flags(self, flags: List[Submission]) -> List[SubmissionLog]:
        raise NotImplementedError

    TICK_TIMEOUT = 3
    RETRY_TIMEOUT = 3
    BIND_TO = '0.0.0.0'
    WORKER_THREADS = 8

    # DON'T TOUCH THIS

    @classmethod
    def main(cls):
        cls().run()

    def __init__(self):
        self.lock = threading.Lock()
        self.tick = -1
        self.targets: Dict[Target, TargetStatus] = {}
        self.service_names: Dict[str, Target] = {}
        self.script_names: Dict[str, str] = {}  # map from id to name
        self.script_queues: Dict[str, List[Target]] = defaultdict(list)

        assert b'\n' not in self.FLAG_REGEX

    def run(self):
        server = nclib.server.TCPServer((self.BIND_TO, PORT))
        scraper_thread = threading.Thread(target=self.scraper_thread)
        scraper_thread.start()
        with concurrent.futures.ThreadPoolExecutor(self.WORKER_THREADS) as executor:
            for client in server:
                executor.submit(self.handle, client)

    def handle(self, sock: nclib.Netcat):
        try:
            line = sock.readln(max_size=100, timeout=1).strip()
            if line == b'submit':
                self.serve_submit(sock)
            elif line == b'getregex':
                self.serve_getregex(sock)
            elif line == b'gettargets':
                self.serve_gettargets(sock)
            elif line == b'gettargetsdumb':
                self.serve_gettargetsdumb(sock)
            elif line == b'getstatus':
                self.serve_getstatus(sock)
        except Exception:
            print('Exception in handle():')
            traceback.print_exc()
        finally:
            sock.close()

    def serve_submit(self, sock: nclib.Netcat):
        lines = sock.recvall(timeout=1)
        if not lines:
            return
        submissions = []
        for line in lines.splitlines():
            try:
                line = line.decode()
                submission = Submission.parse(line)
                submissions.append(submission)

            except Exception:
                print('Exception during submit parsing:')
                traceback.print_exc()

        try:
            results = self.submit_flags(submissions)
        except Exception:
            print('Exception during submit:')
            traceback.print_exc()
            return

        for result in results:
            if result.result == SubmissionResult.SELF:
                self.untarget_host_port(result.submission.target.host, result.submission.target.port)
            elif result.result == SubmissionResult.OK:
                print('BREAD')
                sock.sendline(result.submission.flag)
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

    def serve_getregex(self, sock: nclib.Netcat):
        sock.sendln(self.FLAG_REGEX)

    def serve_gettargets(self, sock: nclib.Netcat):
        script_id = sock.readln(max_size=100, timeout=1).strip().decode()
        script_name = sock.readln(max_size=100, timeout=1).strip().decode()
        service_name = sock.readln(max_size=100, timeout=1).strip().decode()
        n = int(sock.readln(max_size=100, timeout=1).strip().decode())
        self.script_names[script_id] = script_name
        targets = self.get_targets_for_script(script_id, service_name, n)
        for target in targets:
            sock.sendln(target.dump().encode())

    def serve_gettargetsdumb(self, sock: nclib.Netcat):
        service_name = sock.readln(max_size=100, timeout=1).strip().decode()

        targets = self.get_targets_for_tick(service_name, self.tick)
        for target in targets:
            sock.sendln(target.dump().encode())

    def serve_getstatus(self, sock: nclib.Netcat):
        sock.sendln(b'TODO')
        breakpoint()

    def scraper_thread(self):
        while True:
            try:
                status = self.get_status()
            except Exception:
                print('Error getting status:')
                traceback.print_exc()
                time.sleep(10)
                continue

            if status.tick == self.tick:
                time.sleep(10)
                continue
            self.ingest_status(status)

    def ingest_status(self, gamestatus: GameStatus):
        with self.lock:
            self.tick = gamestatus.tick

            for target in gamestatus.targets:
                self.service_names[target.name] = target.target

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

    def get_targets_for_script(self, script_id: str, service_name: str, n: int) -> List[Target]:
        if service_name not in self.service_names:
            print('Warning: someone requested unknown service', repr(service_name))
            return []

        result = None
        with self.lock:
            if len(self.script_queues[script_id]) >= n:
                result, self.script_queues[script_id] = self.script_queues[script_id][:n], self.script_queues[script_id][n:]

        if result is None:
            newstuff = []
            for target, status in self.targets.items():
                if not target.same_service(self.service_names[service_name]):
                    continue
                if status.retired:
                    continue
                if status.script_status[script_id].runs >= self.RETRY_TIMEOUT:
                    continue
                status.script_status[script_id].runs += 1
                newstuff.append(target)
            random.shuffle(newstuff)

            with self.lock:
                self.script_queues[script_id].extend(newstuff)
                result, self.script_queues[script_id] = self.script_queues[script_id][:n], self.script_queues[script_id][n:]

        return result

    def get_targets_for_tick(self, service_name: str, tick: int) -> List[Target]:
        if service_name not in self.service_names:
            print('Warning: someone requested unknown service', repr(service_name))
            return []

        result = []
        for target, status in self.targets.items():
            if not target.same_service(self.service_names[service_name]):
                continue
            if status.tick_last_seen != tick:
                continue
            result.append(target)

        return result
