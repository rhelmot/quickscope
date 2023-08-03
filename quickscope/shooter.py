from typing import List, Optional, Tuple, Union, Set, Dict, Iterable, Any, Protocol
import subprocess
import pathlib
import datetime
import select
import time
import os
import sys
import argparse
import re
import hashlib
import threading
import psutil
from dataclasses import dataclass
import queue
import resource
import logging
import signal
import platform

import nclib

from .common import PORT, Target, Submission, Team, Service, setup_logging, ScriptResult, ScriptMetrics
from .statuspage import statuspage, StatusServer, StatusHandler


logger = logging.getLogger(__name__)

SERVICE_NAME_RE = re.compile(br'x-service-name: ([-\w_=+,./?]+)')

parser = argparse.ArgumentParser('quickscope')
parser.add_argument('--corpus', help='A directory of exploits to fire')
parser.add_argument('--script', help='A single script to fire')
parser.add_argument('--server', help='The shooter tracker to connect to', default='172.31.2.25:%d' % PORT)
parser.add_argument('--procs', help='The level of parallelism to use', type=int)
parser.add_argument('--adaptive-procs', help='Measure system load to determine level of parallelism',
                    action='store_true')
parser.add_argument('--host', help='The single host to shoot at')
parser.add_argument('--port', help='The single port to shoot at', type=int)
parser.add_argument('--flag-id', help='The single flag id to shoot at')
parser.add_argument('--everyone', help='Fire at all live targets and quit', action='store_true')
parser.add_argument('--forever', help='Fire at all live targets until the end of time', action='store_true')
parser.add_argument('--batch', help='Tunes the number of targets which are claimed at once', type=int, default=1)
parser.add_argument('--logdir', help='Directory to store logs in')
parser.add_argument('--no-stdout', help='Disable printing exploit logs to stdout', action='store_true')
parser.add_argument('--timeout', help='Timeout (seconds) for each exploit run', type=int)
parser.add_argument('--mem-limit', help='Memory limit to impose on exploit scripts (GB)', type=float, default=2)
parser.add_argument('--status-html', help='Dump status to file as html and exit')
parser.add_argument('--status-server', help='Serve status on given addr:port forever')
parser.add_argument('--corpus-hints', help='Use the name of the first directory level inside a corpus as a hint for the name of the service a script targets', action='store_true')
parser.add_argument('--submit', help='Pipe stdin to the flag submission service', action='store_true')

class ShooterArgs(argparse.Namespace):
    corpus: Optional[str]
    script: Optional[str]
    server: str
    procs: Optional[int]
    adaptive_procs: bool
    host: Optional[str]
    port: Optional[int]
    flag_id: Optional[str]
    everyone: Optional[bool]
    forever: Optional[bool]
    batch: int
    logdir: Optional[str]
    no_stdout: bool
    timeout: Optional[int]
    mem_limit: float
    status_html: Optional[str]
    status_server: Optional[str]
    corpus_hints: bool
    submit: bool
    service: Optional[str]
    team: Optional[str]

class NotAnExploit(ValueError):
    pass

@dataclass
class Single:
    host: str
    port: int
    flag_id: Optional[str]

@dataclass
class Everyone:
    pass

@dataclass
class Forever:
    pass

TargetMode = Union[Single, Everyone, Forever]

def parse_target_mode(args: ShooterArgs) -> TargetMode:
    results: List[TargetMode] = []
    if args.forever:
        results.append(Forever())
    if args.everyone:
        results.append(Everyone())
    if args.flag_id is not None or args.host is not None or args.port is not None:
        if args.host is None or args.port is None:
            sys.stderr.write("Must provide both of --host/--port or none at all\n")
            sys.stderr.flush()
            sys.exit(1)
        results.append(Single(host=args.host, port=args.port, flag_id=args.flag_id))

    if len(results) != 1:
        sys.stderr.write("Must provide exactly one of --everyone, --forever, or --host/--port/--flag-id\n")
        sys.stderr.flush()
        sys.exit(1)

    return results[0]

def get_flag_regex(server: str) -> re.Pattern[bytes]:
    sock = nclib.Netcat(server)
    sock.sendln(b'getregex')
    return re.compile(sock.readln().strip())

class ScriptManager:
    def __init__(self, script: str, server: str, batch: int, target_mode: TargetMode, script_shortname: str, toplevel: bool = False, service_hint: Optional[str] = None):
        self.server: str = server
        self.script_name: str = script
        self.script_shortname = script_shortname
        self.toplevel: bool = toplevel
        service_name, script_hash = get_script_service_name_and_hash(script, service_hint)
        if script_hash is None:
            raise NotAnExploit(f"Please put `x-service-name: service name` somewhere in {script}, or put it in a .shooterignore file")
        if service_name is None:
            raise NotAnExploit()
        self.service_name: str = service_name
        self.script_hash: str = script_hash
        if not os.access(self.script_name, os.X_OK):
            if not self.script_name.endswith('.py'):
                raise NotAnExploit(script + " is not executable - how do I run it?")

        self.batch: int = batch
        self.target_mode: TargetMode = target_mode
        self.eof: bool = False
        self.buffer: List[Target] = []

    def _buffer_targets(self) -> None:
        if self.eof:
            return

        if isinstance(self.target_mode, Forever):
            sock = nclib.Netcat(self.server, raise_timeout=True)
            sock.sendln(b'gettargets')
            sock.sendln(self.script_hash)
            sock.sendln(self.script_name)
            sock.sendln(self.service_name)
            sock.sendln(str(self.batch).encode())

            try:
                lines = sock.recvall(timeout=10).splitlines()
            except nclib.NetcatTimeout:
                logger.warning("Server did not respond with target list")
                self.eof = True
                return

            self.buffer.extend(Target.from_json(line.decode()) for line in lines)
            if not self.buffer:
                self.eof = True
        elif isinstance(self.target_mode, Everyone):
            sock = nclib.Netcat(self.server, raise_timeout=True)
            sock.sendln(b'gettargetsdumb')
            sock.sendln(self.service_name)

            try:
                lines = sock.recvall(timeout=10).splitlines()
            except nclib.NetcatTimeout:
                logger.warning("Server did not respond with target list")
                self.eof = True
                return

            self.buffer.extend(Target.from_json(line.decode()) for line in lines)
            self.eof = True
        elif isinstance(self.target_mode, Single):
            self.buffer.append(Target(
                team=Team(name=self.target_mode.host, hostname=self.target_mode.host),
                service=Service(name=str(self.target_mode.port), port=self.target_mode.port),
                flag_id=self.target_mode.flag_id,
            ))
            self.eof = True

    def __iter__(self) -> "ScriptManager":
        return self

    def __next__(self) -> Tuple[str, str, Target]:
        while True:
            if not self.buffer:
                try:
                    self._buffer_targets()
                except nclib.NetcatError:
                    logger.exception('Failed to retrieve targets')
            if not self.buffer:
                if isinstance(self.target_mode, Forever) and self.toplevel:
                    self.eof = False
                    time.sleep(4)
                    continue
                raise StopIteration()
            return self.script_name, self.script_shortname, self.buffer.pop()

class CorpusManager:
    def __init__(self, corpus: str, server: str, batch: int, target_mode: TargetMode, subdir_hints: bool = False):
        if isinstance(target_mode, Single):
            sys.stderr.write("Error: cannot specify --corpus and --host/--port/--flag-id\n")
            sys.stderr.flush()
            sys.exit(1)

        self.corpus: str = corpus
        self.server: str = server
        self.batch: int = batch
        self.target_mode: TargetMode = target_mode
        self.subdir_hints: bool = subdir_hints

        self.children: List[ScriptManager] = []
        self.eof: bool = False
        self._collect()

    def _collect(self) -> None:
        if self.eof:
            return
        ignores: List[str] = []
        for root, dirs, files in os.walk(self.corpus):
            subroot = pathlib.Path(root).relative_to(self.corpus)
            subdir_hint = subroot.parts[0] if self.subdir_hints and len(subroot.parts) > 0 and subroot.parts[0] != '.' else None

            if '.shooterignore' in files:
                with open(os.path.join(root, '.shooterignore'), 'r') as fp:
                    lines = fp.read().splitlines()
                ignores.extend(os.path.join(root, line) for line in lines)
                ignores.extend(os.path.join(root, '**', line) for line in lines)

            for stem in files:
                if stem == '.shooterignore':
                    continue
                filename = os.path.join(root, stem)
                if any(pathlib.Path(filename).match(pattern) for pattern in ignores):
                    continue
                try:
                    child = ScriptManager(filename, self.server, self.batch, self.target_mode, str(pathlib.Path(filename).relative_to(self.corpus)), service_hint=subdir_hint)
                except NotAnExploit as e:
                    if e.args:
                        logger.warning("%s", e.args[0])
                else:
                    self.children.append(child)
            dirs[:] = [stem for stem in dirs if not any((pathlib.Path(root) / stem).match(pattern) for pattern in ignores)]
        self.eof = True

    def __iter__(self) -> "CorpusManager":
        return self

    def __next__(self) -> Tuple[str, str, Target]:
        while True:
            if not self.children:
                self._collect()
            try:
                child = self.children.pop(0)
            except IndexError:
                if isinstance(self.target_mode, Forever):
                    self.eof = False
                    time.sleep(4)
                    continue
                else:
                    raise StopIteration()

            try:
                result = next(child)
            except StopIteration:
                continue

            self.children.append(child)
            return result

class Pool(Protocol):
    def apply(self, iterator: Iterable[Tuple[str, str, Target]], *args: Any, **kwargs: Any) -> None:
        ...

class SynchronousPool:
    def apply(self, iterator: Iterable[Tuple[str, str, Target]], *args: Any, **kwargs: Any) -> None:
        for script, script_shortname, target in iterator:
            kwargss: Dict[str, Any] = kwargs | {'script_shortname': script_shortname}
            shoot(script, target, *args, **kwargss)

class AsyncPool:
    def __init__(self, procs: int):
        self.queue: "queue.Queue[Tuple[str, str, Target]]" = queue.Queue(maxsize=1)
        self.threads = [threading.Thread(target=self.worker, daemon=True) for _ in range(procs)]
        self.args: Tuple[Any, ...] = ()
        self.kwargs: Dict[str, Any] = {}
        for thread in self.threads:
            thread.start()

    def apply(self, iterator: Iterable[Tuple[str, str, Target]], *args: Any, **kwargs: Any) -> None:
        self.args = args
        self.kwargs = kwargs
        for script, shortname, target in iterator:
            self.queue.put((script, shortname, target), block=True)
        self.queue.join()

    def worker(self) -> None:
        while True:
            script, shortname, target = self.queue.get(block=True)
            try:
                kwargs: Dict[str, Any] = self.kwargs | {'script_shortname': shortname}
                shoot(script, target, *self.args, **kwargs)
            except:
                logger.exception("Failed to shoot")
            finally:
                self.queue.task_done()

class AdaptivePool:
    # warning: instances of this class will never be garbage collected

    def __init__(self) -> None:
        self.cpu_utilization: float = 0.0
        self.mem_utilization: float = 0.0
        self.watcher_thread: threading.Thread = threading.Thread(target=self.load_watcher, daemon=True)
        self.watcher_thread.start()
        self.worker_threads: List[threading.Thread] = []

        self.args: Tuple[Any, ...] = ()
        self.kwargs: Dict[str, Any] = {}
        self.queue: queue.Queue[Tuple[str, str, Target]] = queue.Queue(maxsize=1)
        self.lock: threading.Lock = threading.Lock()
        self.live_tasks: int = 0
        self.target_threads: int = 1

    def load_watcher(self) -> None:
        while True:
            self.cpu_utilization = psutil.cpu_percent(1) / 100.0
            self.mem_utilization = psutil.virtual_memory().percent / 100.0

            if self.live_tasks == self.target_threads and self.cpu_utilization < 0.9 and self.mem_utilization < 0.75:
                self.target_threads += 1
                logger.info("Increasing target threads to %s", self.target_threads)
            elif (self.cpu_utilization > 0.99 or self.mem_utilization > 0.95) and self.target_threads > 1:
                self.target_threads -= 1
                logger.info("Decreasing target threads to %s", self.target_threads)

            while self.worker_threads and not self.worker_threads[-1].is_alive():
                self.worker_threads[-1].join()
                self.worker_threads.pop(-1)

            while len(self.worker_threads) < self.target_threads:
                self.worker_threads.append(
                    threading.Thread(target=self.worker, args=(len(self.worker_threads),), daemon=True)
                )
                self.worker_threads[-1].start()

    def apply(self, iterator: Iterable[Tuple[str, str, Target]], *args: Any, **kwargs: Any) -> None:
        self.args = args
        self.kwargs = kwargs
        for script, shortname, target in iterator:
            self.queue.put((script, shortname, target), block=True)
        self.queue.join()

    def worker(self, ident: int) -> None:
        while True:
            if ident >= self.target_threads:
                return
            script, shortname, target = self.queue.get(block=True)
            with self.lock:
                self.live_tasks += 1
            try:
                kwargs: Dict[str, Any] = self.kwargs | {'script_shortname': shortname}
                shoot(script, target, *self.args, **kwargs)
            except:
                logger.exception("Failed to shoot")
            finally:
                self.queue.task_done()
                with self.lock:
                    self.live_tasks -= 1

def get_script_service_name_and_hash(script: str, service_hint: Optional[str] = None) -> Tuple[Optional[str], Optional[str]]:
    with open(script, 'rb') as fp:
        script_bytes = fp.read()
    match = SERVICE_NAME_RE.search(script_bytes)
    h = hashlib.md5()
    h.update(script_bytes)
    hd = h.hexdigest()
    if b'x-shooter-ignore' in script_bytes:
        return None, hd
    if match:
        service = match.group(1).decode()
        return service, hd
    if service_hint is not None:
        return service_hint, hd
    return None, None

LIVE_PROCESSES: Set[subprocess.Popen[bytes]] = set()

def kill_live_processes() -> None:
    for proc in list(LIVE_PROCESSES):
        proc.kill()

def shoot(
    script: str,
    target: Target,
    timeout: Optional[int],
    logdir: Optional[str],
    flag_regex: re.Pattern[bytes],
    use_stdout: bool,
    mem_limit: float,
    script_shortname: Optional[str] = None,
    corpus_hash: Optional[str] = None,
) -> None:
    if timeout is None:
        timeout = 999999999
    start_time = datetime.datetime.now()
    deadline = time.time() + timeout
    cmd = [os.path.join('.', os.path.basename(script))]
    env = dict(os.environ)
    for name in ('team', 'team_name', 'teamname'):
        env[name] = env[name.upper()] = target.team.name
    for name in ('host', 'victim', 'enemy'):
        env[name] = env[name.upper()] = target.team.hostname
    for name in ('port',):
        env[name] = env[name.upper()] = str(target.service.port)
    if target.flag_id is not None:
        for name in ('flagid', 'flag_id', 'fid', 'id'):
            env[name] = env[name.upper()] = target.flag_id

    if not os.access(script, os.X_OK):
        if script.endswith('.py'):
            cmd.insert(0, 'python3')

    with open(script, 'rb') as fp:
        script_bytes = fp.read()
    h = hashlib.md5()
    h.update(script_bytes)
    script_hash = h.hexdigest()

    def preexec_limits() -> None:
        size_bytes = int(mem_limit * 1024 * 1024 * 1024)
        #resource.setrlimit(resource.RLIMIT_STACK, (size_bytes, size_bytes))
        resource.setrlimit(resource.RLIMIT_DATA, (size_bytes, size_bytes))
        os.setpgrp()

    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        cwd=os.path.dirname(os.path.realpath(script)),
        preexec_fn=preexec_limits,
        env=env,
    )
    assert proc.stdout is not None
    LIVE_PROCESSES.add(proc)
    head_buf: List[bytes] = []
    tail_buf: List[bytes] = []
    buf_full = False
    BUF_SIZE = 20
    LINE_SIZE = 1024*4
    seen_flags: List[bytes] = []

    hit_timeout = False
    while True:
        r, _, _ = select.select([proc.stdout], [], [], max(0., deadline - time.time()))
        if not r:
            hit_timeout = True
            if use_stdout:
                print('TIMEOUT')
            break
        line = proc.stdout.readline(LINE_SIZE)
        if not line:
            break
        if use_stdout:
            sys.stdout.buffer.write(line)
            sys.stdout.buffer.flush()
        if len(head_buf) < BUF_SIZE:
            head_buf.append(line)
        else:
            tail_buf.append(line)
            if len(tail_buf) >= BUF_SIZE:
                tail_buf.pop(0)
                buf_full = True

        for flag in flag_regex.finditer(line):
            seen_flags.append(flag.group(0))
            while True:
                try:
                    SUBMISSION_QUEUE.put(Submission(flag=flag.group(0), target=target, script=script))
                except queue.Full:
                    logger.warning("Submission queue is full")
                    time.sleep(5)
                else:
                    break

    try:
        code = proc.wait(deadline - time.time())
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        status = ScriptResult.SUCCESS if code == 0 else ScriptResult.FAILURE
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        code = proc.wait()
        status = ScriptResult.TIMEOUT
    LIVE_PROCESSES.remove(proc)

    metrics = ScriptMetrics(
            script=script_shortname or script,
            script_hash=script_hash,
            corpus_hash=corpus_hash,
            target=target,
            start_time=start_time,
            duration=datetime.datetime.now() - start_time,
            status=status,
            flags_seen=len(seen_flags),
            flags=','.join(f.decode('latin-1') for f in seen_flags),
            host=platform.node(),
            exit_code=code,
    )
    METRICS_QUEUE.put(metrics)

    if logdir is not None:
        log_filename = os.path.join(logdir, script_shortname or os.path.basename(script), start_time.isoformat() + '-' + target.team.name + '.log')
        pathlib.Path(log_filename).parent.mkdir(parents=True, exist_ok=True)
        with open(log_filename, 'wb') as fp2:
            fp2.write(metrics.to_json().encode() + b'\n')
            fp2.writelines(head_buf)
            if buf_full:
                fp2.write(b'...\n')
            fp2.writelines(tail_buf)
            if hit_timeout:
                fp2.write(b'TIMEOUT\n')


SUBMISSIONS_DONE: bool = False
SUBMISSION_QUEUE: "queue.Queue[Submission]" = queue.Queue(maxsize=10000)
METRICS_QUEUE: "queue.Queue[ScriptMetrics]" = queue.Queue(maxsize=10000)
NOTIFIED_SOCKS: List[nclib.Netcat] = []
FLAG_MAPPING: Dict[bytes, Submission] = {}

def metrics_routine(server: str, debounce: Union[int, float]) -> None:
    while not SUBMISSIONS_DONE:
        buffer = set()
        deadline = time.time() + debounce
        while True:
            try:
                metric = METRICS_QUEUE.get(block=True, timeout=deadline - time.time())
            except (queue.Empty, ValueError):
                break
            else:
                buffer.add(metric)

        if buffer:
            try:
                sock = nclib.Netcat(server)
            except:
                logger.exception('Could not connect to server for metrics submission')
                continue
            try:
                sock.sendln(b'pubmetrics')
                sock.send(b''.join(s.to_json().encode() + b'\n' for s in buffer))
                sock.close()
            except:
                logger.exception('Failed to submit metrics')

def submission_routine(server: str, debounce: Union[int, float]) -> None:
    buffer = set()
    while not SUBMISSIONS_DONE:
        deadline = time.time() + debounce
        while True:
            try:
                submission = SUBMISSION_QUEUE.get(block=True, timeout=deadline - time.time())
            except (queue.Empty, ValueError):  # ValueError = negative timeout
                break
            else:
                buffer.add(submission)
                FLAG_MAPPING[submission.flag.strip()] = submission

        if buffer:
            try:
                sock = nclib.Netcat(server)
            except:
                logger.exception('Could not connect to server for flag submission')
                continue
            try:
                logger.info("Submitting %d flags", len(buffer))
                sock.sendln(b'submit')
                sock.send(b''.join(s.to_json().encode() + b'\n' for s in buffer))
                sock.shutdown_wr()
            except:
                logger.exception('Failed to submit flags')
            else:
                buffer.clear()
            NOTIFIED_SOCKS.append(sock)

def notification_routine() -> None:
    while not SUBMISSIONS_DONE or NOTIFIED_SOCKS:
        r, _, _ = nclib.select(NOTIFIED_SOCKS, [], [], timeout=1)
        for sock in r:
            line = sock.recvln()
            if not line:
                NOTIFIED_SOCKS.remove(sock)
            else:
                submission = FLAG_MAPPING.get(line.strip(), None)
                if submission is None:
                    logger.warning("Got points on unknown flag?")
                else:
                    logger.info("Got points on %s:%s", submission.target.team.name, submission.target.service.name)

def submit_routine(server: str, target: Target, script: str) -> None:
    flag_regex = get_flag_regex(server)
    for line in sys.stdin.buffer:
        for flag in flag_regex.finditer(line):
            SUBMISSION_QUEUE.put(Submission(flag=flag.group(0), target=target, script=script))

def main() -> None:
    global SUBMISSIONS_DONE
    setup_logging()
    ctrl_c_times = 0
    def force_exit(*args: Any) -> None:
        nonlocal ctrl_c_times
        global SUBMISSIONS_DONE
        if ctrl_c_times == 0:
            sys.stderr.write("CTRL-C again to force exit\n")
            sys.stderr.flush()
            ctrl_c_times += 1
        else:
            sys.stderr.write("Cancelling all tasks and exiting\n")
            sys.stderr.flush()
            SUBMISSIONS_DONE = True
            sys.exit()

    def on_shutdown(*args: Any) -> None:
        global SUBMISSIONS_DONE
        SUBMISSIONS_DONE = True
        sys.exit()

    args = parser.parse_args(sys.argv[1:], namespace=ShooterArgs())
    if args.status_html:
        with open(args.status_html, 'w', encoding='utf-8') as fp:
            fp.write(statuspage(args.server))
        return
    if args.status_server:
        host, port_s = args.status_server.split(':')
        port = int(port_s)
        server = StatusServer((host, port), StatusHandler, args.server)
        print(f'serving on http://{args.status_server}/')
        server.serve_forever()
        return

    signal.signal(signal.SIGINT, force_exit)
    signal.signal(signal.SIGTERM, on_shutdown)

    target_mode = parse_target_mode(args)
    debounce = 5 if isinstance(target_mode, Forever) or args.submit else 1

    submission_thread = threading.Thread(target=submission_routine, args=(args.server, debounce))
    notification_thread = threading.Thread(target=notification_routine)

    if args.submit:
        if args.script is None or args.host is None or args.port is None:
            sys.stderr.write("Error: must specify --script, --host, and --port so we know the providence of flags")
            sys.stderr.flush()
            sys.exit(1)

        submission_thread.start()
        notification_thread.start()

        assert isinstance(target_mode, Single)
        target = Target(
            team=Team(name=target_mode.host, hostname=target_mode.host),
            service=Service(name=str(target_mode.port), port=target_mode.port),
            flag_id=target_mode.flag_id,
        )
        submit_routine(args.server, target, args.script)
        SUBMISSIONS_DONE = True
    else:
        submission_thread.start()
        notification_thread.start()

        mgr: Iterable[Tuple[str, str, Target]]
        if args.corpus is not None:
            if args.script is not None:
                sys.stderr.write("Error: only specify one of --corpus or --script\n")
                sys.stderr.flush()
                sys.exit(1)
            mgr = CorpusManager(args.corpus, args.server, args.batch, target_mode, args.corpus_hints)
        elif args.script is not None:
            mgr = ScriptManager(args.script, args.server, args.batch, target_mode, args.script, toplevel=True)
        else:
            sys.stderr.write("Error: must specify one of --corpus or --script\n")
            sys.stderr.flush()
            sys.exit(1)

        pool: Pool
        if args.adaptive_procs:
            pool = AdaptivePool()
        elif args.procs:
            pool = AsyncPool(args.procs)
        else:
            pool = SynchronousPool()

        metrics_thread = threading.Thread(target=metrics_routine, args=(args.server, debounce))
        metrics_thread.start()

        pool.apply(
            mgr,
            timeout=args.timeout,
            logdir=args.logdir,
            flag_regex=get_flag_regex(args.server),
            use_stdout=not args.no_stdout,
            mem_limit=args.mem_limit,
        )

        SUBMISSIONS_DONE = True
        metrics_thread.join()

    submission_thread.join()
    notification_thread.join()

if __name__ == '__main__':
    main()
