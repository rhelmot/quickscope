import subprocess
from typing import List, Optional, Tuple, Union
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
import traceback
from dataclasses import dataclass
from queue import Queue, Empty

import nclib

from .common import PORT, Target, Submission

SERVICE_NAME_RE = re.compile(br'x-service-name: ([-\w_=+,./?]+)')

parser = argparse.ArgumentParser('The shooter. Pew pew!')
parser.add_argument('--corpus', help='A directory of exploits to fire')
parser.add_argument('--script', help='A single script to fire')
parser.add_argument('--server', help='The shooter tracker to connect to', default='172.29.0.3:%d' % PORT)
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
parser.add_argument('--timeout', help='Timeout (seconds) for each exploit run', type=int)

class NotAnExploit(ValueError):
    pass

@dataclass
class Single:
    host: str
    port: int
    flag_id: str

@dataclass
class Everyone:
    pass

@dataclass
class Forever:
    pass

TargetMode = Union[Single, Everyone, Forever]

def parse_target_mode(args) -> TargetMode:
    results = []
    if args.forever:
        results.append(Forever())
    if args.everyone:
        results.append(Everyone())
    if args.flag_id is not None or args.host is not None or args.port is not None:
        if args.flag_id is None or args.host is None or args.port is None:
            print("Must provide all of --host/--port/--flag-id or none at all")
            sys.exit(1)
        results.append(Single(host=args.host, port=args.port, flag_id=args.flag_id))

    if len(results) != 1:
        print("Must provide exactly one of --everyone, --forever, or --host/--port/--flag-id")
        sys.exit(1)

    return results[0]

def get_flag_regex(server):
    sock = nclib.Netcat(server)
    sock.sendln(b'getregex')
    return re.compile(sock.readln().strip())

class ScriptManager:
    def __init__(self, script: str, server: str, batch: int, target_mode: TargetMode, toplevel=False):
        self.server = server
        self.script_name = script
        self.toplevel = toplevel
        self.service_name, self.script_hash = get_script_service_name_and_hash(script)
        if self.script_hash is None:
            raise NotAnExploit("Please put `x-service-name: service name` (or x-shooter-ignore) somewhere in " + script)
        if self.service_name is None:
            raise NotAnExploit()
        if not os.access(self.script_name, os.X_OK):
            if not self.script_name.endswith('.py'):
                raise NotAnExploit(script + " is not executable - how do I run it?")

        self.batch = batch
        self.target_mode = target_mode
        self.eof = False
        self.buffer = []

    def _buffer_targets(self):
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
                print("Warning: server did not respond with target list")
                self.eof = True
                return

            self.buffer.extend(Target.parse(line) for line in lines)
            if not self.buffer:
                self.eof = True
        elif isinstance(self.target_mode, Everyone):
            sock = nclib.Netcat(self.server, raise_timeout=True)
            sock.sendln(b'gettargetsdumb')
            sock.sendln(self.service_name)

            try:
                lines = sock.recvall(timeout=10).splitlines()
            except nclib.NetcatTimeout:
                print("Warning: server did not respond with target list")
                self.eof = True
                return

            self.buffer.extend(Target.parse(line) for line in lines)
            self.eof = True
        elif isinstance(self.target_mode, Single):
            self.buffer.append(Target(self.target_mode.host, self.target_mode.port, self.target_mode.flag_id))
            self.eof = True

    def __iter__(self):
        return self

    def __next__(self):
        while True:
            if not self.buffer:
                try:
                    self._buffer_targets()
                except nclib.NetcatError:
                    traceback.print_exc()
                    print('Warning: failed to retrieve targets')
            if not self.buffer:
                if isinstance(self.target_mode, Forever) and self.toplevel:
                    self.eof = False
                    time.sleep(4)
                    continue
                raise StopIteration()
            return self.script_name, self.buffer.pop()

class CorpusManager:
    def __init__(self, corpus, server, batch, target_mode):
        if isinstance(target_mode, Single):
            print("Error: cannot specify --corpus and --host/--port/--flag-id")
            sys.exit(1)

        self.corpus = corpus
        self.server = server
        self.batch = batch
        self.target_mode = target_mode

        self.children = []
        self.eof = False
        self._collect()

    def _collect(self):
        if self.eof:
            return
        for root, dirs, files in os.walk(self.corpus):
            for stem in files:
                filename = os.path.join(root, stem)
                try:
                    child = ScriptManager(filename, self.server, self.batch, self.target_mode)
                except NotAnExploit as e:
                    if e.args:
                        print(e.args[0])
                else:
                    self.children.append(child)
        self.eof = True

    def __iter__(self):
        return self

    def __next__(self):
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

class SynchronousPool:
    def apply(self, iterator, *args, **kwargs):
        for script, target in iterator:
            shoot(script, target, *args, **kwargs)

class AsyncPool:
    def __init__(self, procs: int):
        self.queue = Queue(maxsize=1)
        self.threads = [threading.Thread(target=self.worker, daemon=True) for _ in range(procs)]
        self.args = None
        self.kwargs = None
        for thread in self.threads:
            thread.start()

    def apply(self, iterator, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs
        for script, target in iterator:
            self.queue.put((script, target), block=True)
        self.queue.join()

    def worker(self):
        while True:
            script, target = self.queue.get(block=True)
            try:
                shoot(script, target, *self.args, **self.kwargs)
            except:
                traceback.print_exc(file=sys.stderr)
            finally:
                self.queue.task_done()

class AdaptivePool:
    # warning: instances of this class will never be garbage collected

    def __init__(self):
        self.cpu_utilization = 0.0
        self.mem_utilization = 0.0
        self.watcher_thread = threading.Thread(target=self.load_watcher, daemon=True)
        self.watcher_thread.start()
        self.worker_threads: List[threading.Thread] = []

        self.args = None
        self.kwargs = None
        self.queue = Queue(maxsize=1)
        self.lock = threading.Lock()
        self.live_tasks = 0
        self.target_threads = 1

    def load_watcher(self):
        while True:
            self.cpu_utilization = psutil.cpu_percent(1) / 100.0
            self.mem_utilization = psutil.virtual_memory() / 100.0

            if self.live_tasks == self.target_threads and self.cpu_utilization < 0.9 and self.mem_utilization < 0.75:
                self.target_threads += 1
            elif self.cpu_utilization > 0.99 or self.mem_utilization > 0.95 and self.target_threads > 1:
                self.target_threads -= 1

            while self.worker_threads and not self.worker_threads[-1].is_alive():
                self.worker_threads[-1].join()
                self.worker_threads.pop(-1)

            while len(self.worker_threads) < self.target_threads:
                self.worker_threads.append(
                    threading.Thread(target=self.worker, args=(len(self.worker_threads),), daemon=True)
                )
                self.worker_threads[-1].start()

    def apply(self, iterator, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs
        for script, target in iterator:
            self.queue.put((script, target), block=True)
        self.queue.join()

    def worker(self, ident):
        while True:
            if ident >= self.target_threads:
                return
            script, target = self.queue.get(block=True)
            with self.lock:
                self.live_tasks += 1
            try:
                shoot(script, target, *self.args, **self.kwargs)
            except:
                traceback.print_exc(file=sys.stderr)
            finally:
                self.queue.task_done()
                with self.lock:
                    self.live_tasks -= 1

def get_script_service_name_and_hash(script) -> Tuple[Optional[str], Optional[str]]:
    with open(script, 'rb') as fp:
        script_bytes = fp.read()
    match = SERVICE_NAME_RE.search(script_bytes)
    h = hashlib.md5()
    h.update(script_bytes)
    h = h.hexdigest()
    if b'x-shooter-ignore' in script_bytes:
        return None, h
    if match:
        return match.group(1).decode(), h
    return None, None

LIVE_PROCESSES = set()

def kill_live_processes():
    for proc in list(LIVE_PROCESSES):
        proc.kill()

def shoot(
    script: str,
    target: Target,
    timeout: Optional[int],
    logdir: Optional[str],
    flag_regex: re.Pattern,
):
    if timeout is None:
        timeout = 999999999
    deadline = time.time() + timeout
    cmd = [os.path.join('.', os.path.basename(script)), target.host, str(target.port), target.flag_id]
    if not os.access(script, os.X_OK):
        if script.endswith('.py'):
            cmd.insert(0, 'python3')

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        cwd=os.path.dirname(script)
    )
    LIVE_PROCESSES.add(proc)
    head_buf = []
    tail_buf = []
    buf_full = False
    BUF_SIZE = 20

    hit_timeout = False
    while True:
        r, _, _ = select.select([proc.stdout], [], [], deadline - time.time())
        if not r:
            hit_timeout = True
            break
        line = proc.stdout.readline()
        if not line:
            break
        if len(head_buf) < BUF_SIZE:
            head_buf.append(line)
        else:
            tail_buf.append(line)
            if len(tail_buf) >= BUF_SIZE:
                tail_buf.pop(0)
                buf_full = True

        for flag in flag_regex.finditer(line):
            SUBMISSION_QUEUE.put(Submission(flag=flag.group(0), target=target, script=script))

    try:
        proc.wait(deadline - time.time())
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
    LIVE_PROCESSES.remove(proc)

    if logdir is not None:
        log_filename = os.path.join(logdir, script + '-' + datetime.datetime.now().isoformat())
        pathlib.Path(log_filename).parent.mkdir(parents=True)
        fp = open(log_filename, 'wb')
    else:
        fp = sys.stdout.buffer

    fp.writelines(head_buf)
    if buf_full:
        fp.write(b'...\n')
    fp.writelines(tail_buf)
    if hit_timeout:
        fp.write(b'TIMEOUT\n')

    if logdir is not None:
        fp.close()
    else:
        fp.flush()

SUBMISSIONS_DONE = False
SUBMISSION_QUEUE = Queue(maxsize=10000)

def submission_routine(server, debounce):
    buffer = set()
    while not SUBMISSIONS_DONE:
        deadline = time.time() + debounce
        while True:
            try:
                buffer.add(SUBMISSION_QUEUE.get(block=True, timeout=deadline - time.time()))
            except Empty:
                break

        if buffer:
            try:
                sock = nclib.Netcat(server)
            except:
                traceback.print_exc()
                print('Warning: could not connect to server for flag submission')
                continue
            try:
                sock.sendln(b'submit')
                sock.send(b''.join(s.dump().encode() + b'\n' for s in buffer))
            except:
                traceback.print_exc()
                print('Warning: failed to submit flags')
            else:
                buffer.clear()
            finally:
                sock.close()


def main():
    args = parser.parse_args(sys.argv[1:])
    target_mode = parse_target_mode(args)
    if args.corpus is not None:
        if args.script is not None:
            print("Error: only specify one of --corpus or --script")
            sys.exit(1)
        mgr = CorpusManager(args.corpus, args.server, args.batch, target_mode)
    elif args.script is not None:
        mgr = ScriptManager(args.script, args.server, args.batch, target_mode, toplevel=True)
    else:
        print("Error: must specify one of --corpus or --script")
        sys.exit(1)

    if args.adaptive_procs:
        pool = AdaptivePool()
    elif args.procs:
        pool = AsyncPool(args.procs)
    else:
        pool = SynchronousPool()

    debounce = 5 if isinstance(target_mode, Forever) else 1
    submission_thread = threading.Thread(target=submission_routine, args=(args.server, debounce))
    submission_thread.start()

    pool.apply(
        mgr,
        timeout=args.timeout,
        logdir=args.logdir,
        flag_regex=get_flag_regex(args.server),
    )

    global SUBMISSIONS_DONE
    SUBMISSIONS_DONE = True
    submission_thread.join()

if __name__ == '__main__':
    main()
