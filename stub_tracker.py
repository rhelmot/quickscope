from typing import List
import json
import requests
import nclib

from tracker import Tracker, Submission, SubmissionLog, SubmissionResult, GameStatus, NamedTarget, Target

NO_FLAG_IDS = ['service n', 'service n+1']
PORT_MAPPING = {
    'service n': 8000,
    'service n+1': 8001,
    'service_1': 1234,
}


class StubTracker(Tracker):
    FLAG_REGEX = b'ENO[A-Za-z0-9+\/=]{48}'

    def get_status(self) -> GameStatus:
        game_json = json.loads(requests.get('http://localhost:1338/game.json').text)
        other_ips = requests.get('http://localhost:1338/ips.txt').text.split()

        result = GameStatus(0, [])

        for service_name, status1 in game_json['services'].items():
            for host, status2 in status1.items():
                for tick, flag_ids in status2.items():
                    result.tick = max(int(tick), result.tick)
                    for flag_id in flag_ids:
                        result.targets.append(NamedTarget(Target(host, PORT_MAPPING[service_name], flag_id[0]), service_name))

        for service_name in NO_FLAG_IDS:
            for ip in other_ips:
                result.targets.append(NamedTarget(Target(ip, PORT_MAPPING[service_name], str(result.tick)), service_name))

        return result

    def submit_flags(self, flags: List[Submission]) -> List[SubmissionLog]:
        sock = nclib.Netcat('nc localhost 1337')
        mapping = {}
        for flag in flags:
            mapping[flag.flag] = flag
            sock.sendln(flag.flag)
        sock.shutdown_wr()

        results = []
        while True:
            line = sock.readln(timeout=0.5)
            if not line:
                break
            flag, status_str, *_ = line.split()
            if flag not in mapping:
                continue
            if status_str == 'OK':
                status = SubmissionResult.OK
            elif status_str == 'INV':
                status = SubmissionResult.INVALID
            elif status_str == 'SELF':
                status = SubmissionResult.SELF
            elif status_str == 'OLD':
                status = SubmissionResult.TOO_OLD
            elif status_str == 'DUP':
                status = SubmissionResult.ALREADY_SUBMITTED
            else:
                status = SubmissionResult.UNKNOWN

            results.append(SubmissionLog(mapping[flag], status))
        return results

if __name__ == '__main__':
    StubTracker.main()
