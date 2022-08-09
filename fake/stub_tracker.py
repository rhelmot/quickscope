import threading
import json
import nclib

from quickscope.tracker import Tracker
from quickscope.common import *

PORT_MAPPING = {
    'service_1': 5001,
    'service_2': 5002,
    'service_3': 5003,
    'service_4': 5004,
    'service_5': 5005,
}


class StubTracker(Tracker):
    FLAG_REGEX = b'FLG[A-Za-z0-9+\/=]{8}'

    def get_status(self) -> GameStatus:
        sock = nclib.Netcat('nc 127.0.1.1 1338')
        try:
            game_json = json.loads(sock.recvall().decode())
        finally:
            sock.close()

        result = GameStatus(game_json['tick'], [])

        for service_name, status1 in game_json['services'].items():
            for host, flag_id in status1.items():
                result.targets.append(Target(
                    team=Team(name=host, hostname=host),
                    service=Service(name=service_name, port=PORT_MAPPING[service_name]),
                    flag_id=flag_id,
                ))

        return result

    def submit_flags(self, flags: List[Submission]) -> List[SubmissionLog]:
        sock = nclib.Netcat('nc 127.0.1.1 1337')
        try:
            mapping = {}
            def submit_worker():
                for flag in flags:
                    mapping[flag.flag] = flag
                    sock.sendln(flag.flag)
                sock.shutdown_wr()
            threading.Thread(target=submit_worker).start()

            results = []
            while True:
                line = sock.readln(timeout=0.5)
                if not line:
                    break
                flag, status_str, *_ = line.split()
                if flag not in mapping:
                    continue
                if status_str == b'OK':
                    status = SubmissionResult.OK
                elif status_str == b'INV':
                    status = SubmissionResult.INVALID
                elif status_str == b'SELF':
                    status = SubmissionResult.SELF
                elif status_str == b'OLD':
                    status = SubmissionResult.TOO_OLD
                elif status_str == b'DUP':
                    status = SubmissionResult.ALREADY_SUBMITTED
                else:
                    status = SubmissionResult.UNKNOWN

                results.append(SubmissionLog(mapping[flag], status))
            return results
        finally:
            sock.close()

    def instrument_targets(self, targets):
        return targets

if __name__ == '__main__':
    StubTracker.main()
