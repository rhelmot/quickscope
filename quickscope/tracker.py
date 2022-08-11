import random
import concurrent.futures
import threading
import nclib
import io
import time
from typing import Optional, Set

from .common import *


logger = logging.getLogger(__name__)

class Tracker:
    # HERE'S WHAT YOU IMPLEMENT
    FLAG_REGEX: bytes = NotImplemented

    def get_status(self) -> GameStatus:
        raise NotImplementedError

    def submit_flags(self, flags: List[Submission]) -> List[SubmissionLog]:
        raise NotImplementedError

    def instrument_targets(self, targets: List[Target]) -> List[Target]:
        """
        This is called just before shooting at the given target list - each target in the list will be shot at once.

        This gives the tracker the ability to record that shooting at a target is occurring and to modify the target
        list, for example, to remove targets with rate-limiting imposed.
        """
        raise NotImplementedError

    TICK_TIMEOUT = 3
    RETRY_TIMEOUT = 3
    BIND_TO = '0.0.0.0'
    WORKER_THREADS = 8

    # DON'T TOUCH THIS

    @classmethod
    def main(cls):
        setup_logging()

        root = logging.getLogger()
        buf = io.StringIO()
        sh = logging.StreamHandler(buf)
        fm = logging.Formatter(
            "%(asctime)s - %(name)-25s - %(funcName)-10s - %(levelname)-5s - %(message)s")
        sh.setFormatter(fm)
        root.addHandler(sh)

        sh.setLevel(logging.INFO)
        logger.info("Tracker starting on %s:%s", cls.BIND_TO, PORT)
        sh.setLevel(logging.ERROR)
        cls(logging_memory=buf).run()

    def __init__(self, logging_memory: io.StringIO):
        self.lock = threading.Lock()
        self.tick = -1
        self.targets: Dict[Target, TargetStatus] = {}
        self.script_info: Dict[str, ScriptStatus] = {}  # keyed on hash
        self.script_queues: Dict[str, List[Target]] = defaultdict(list)
        self.logging_memory: io.StringIO = logging_memory
        self.submit_buffer: List[Submission] = []
        self.submit_buffer_lock = threading.Lock()
        self.submit_thread = threading.Thread(target=self._submit_thread, daemon=True)
        self.submit_thread.start()

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
            else:
                raise Exception("not a command", line)
        except Exception:
            logger.exception("Exception in handle()")
        finally:
            sock.close()

    def serve_submit(self, sock: nclib.Netcat):
        lines = sock.recvall(timeout=1)
        if not lines:
            return
        submissions = []
        for line in lines.splitlines():
            try:
                submission = Submission.from_json(line.decode())
                submissions.append(submission)

            except Exception:
                logger.exception("Exception during submit parsing")

        try:
            results = self.submit_flags(submissions)
        except Exception:
            logger.exception("Exception during submit")
            results = []
        self.process_successful_submissions(submissions, results, sock)

    def _submit_thread(self):
        while True:
            time.sleep(10)
            next_batch = None
            with self.submit_buffer_lock:
                if len(self.submit_buffer) > 0:
                    next_batch = self.submit_buffer
                    self.submit_buffer = []
            if next_batch is not None:
                try:
                    results = self.submit_flags(next_batch)
                except Exception:
                    logger.exception("Exception during submit retry")
                    results = []
                self.process_successful_submissions(next_batch, results, None)

    def process_successful_submissions(
            self,
            submissions: List[Submission],
            results: List[SubmissionLog],
            sock: Optional[nclib.Netcat]=None
    ) -> None:
        submissions_set = set(submissions)
        for result in results:
            try:
                submissions_set.remove(result.submission)
            except KeyError:
                pass
            if result.result == SubmissionResult.SELF:
                self.untarget_host_port(result.submission.target)
            elif result.result == SubmissionResult.OK:
                logger.info(
                    "Got points on %s:%s",
                    result.submission.target.team.name,
                    result.submission.target.service.name
                )
                if sock is not None:
                    try:
                        sock.sendline(result.submission.flag)
                    except BrokenPipeError:
                        pass
                self.untarget_target(result.submission.target)
            elif result.result == SubmissionResult.ALREADY_SUBMITTED:
                self.untarget_target(result.submission.target)
            elif result.result == SubmissionResult.INVALID:
                logger.warning("Getting bogus flags for %s", result.submission.target)
                pass
            elif result.result == SubmissionResult.UNKNOWN:
                pass
            elif result.result == SubmissionResult.TOO_OLD:
                pass
            else:
                logger.error("Bad submission result: %s (is your submitter misbehaving?)",
                             result.result)

        with self.submit_buffer_lock:
            self.submit_buffer.extend(submissions_set)

    def serve_getregex(self, sock: nclib.Netcat):
        sock.sendln(self.FLAG_REGEX)

    def serve_gettargets(self, sock: nclib.Netcat):
        script_id = sock.readln(max_size=100, timeout=1).strip().decode()
        script_name = sock.readln(max_size=100, timeout=1).strip().decode()
        service_name = sock.readln(max_size=100, timeout=1).strip().decode()
        n = int(sock.readln(max_size=100, timeout=1).strip().decode())
        if script_id not in self.script_info:
            with self.lock:
                if script_id not in self.script_info:
                    self.script_info[script_id] = ScriptStatus(
                        filename=script_name,
                        service_name=service_name,
                        tick_first_seen=self.tick,
                        tick_last_seen=self.tick,
                    )
        self.script_info[script_id].tick_last_seen = self.tick
        targets = self.get_targets_for_script(script_id, service_name, n)
        targets = self.instrument_targets(targets)
        for target in targets:
            sock.sendln(target.to_json().encode())

    def serve_gettargetsdumb(self, sock: nclib.Netcat):
        service_name = sock.readln(max_size=100, timeout=1).strip().decode()

        targets = self.get_targets_for_tick(service_name, self.tick)
        targets = self.instrument_targets(targets)
        for target in targets:
            sock.sendln(target.to_json().encode())

    def serve_getstatus(self, sock: nclib.Netcat):
        result = ShooterStatus(
            tick=self.tick,
            script_info=self.script_info,
            targets=dict(self.targets),
            tick_timeout=self.TICK_TIMEOUT,
            retry_timeout=self.RETRY_TIMEOUT,
            error_log=self.logging_memory.getvalue(),
        )
        sock.send(result.to_json().encode())

    def scraper_thread(self):
        while True:
            try:
                status = self.get_status()
            except Exception:
                logger.exception("Error getting status")
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
                if target in self.targets:
                    self.targets[target].tick_last_seen = gamestatus.tick
                else:
                    self.targets[target] = TargetStatus(tick_first_seen=gamestatus.tick, tick_last_seen=gamestatus.tick)

            to_remove = []
            for target, status in self.targets.items():
                if status.tick_last_seen < gamestatus.tick - self.TICK_TIMEOUT:
                    to_remove.append(target)
            for target in to_remove:
                self.targets.pop(target)

    def untarget_host_port(self, bad_target):
        with self.lock:
            for target, status in self.targets.items():
                if target.same_process(bad_target):
                    status.retired = True

    def untarget_target(self, target: Target):
        try:
            self.targets[target].retired = True
        except KeyError:
            pass

    def get_targets_for_script(self, script_id: str, service_name: str, n: int) -> List[Target]:
        result = None
        found_one = False
        with self.lock:
            if len(self.script_queues[script_id]) >= n:
                result, self.script_queues[script_id] = self.script_queues[script_id][:n], self.script_queues[script_id][n:]
                found_one = True

        if result is None:
            newstuff = []
            for target, status in self.targets.items():
                if target.service.name != service_name:
                    continue
                found_one = True
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

        if not found_one:
            logger.warning("Someone requested unknown service %s", repr(service_name))
        return result

    def get_targets_for_tick(self, service_name: str, tick: int) -> List[Target]:
        result = []
        found_one = False
        for target, status in self.targets.items():
            if target.service.name != service_name:
                continue
            found_one = True
            if status.tick_last_seen != tick:
                continue
            result.append(target)

        if not found_one:
            logger.warning("Someone requested unknown service %s", repr(service_name))
        return result
