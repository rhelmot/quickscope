from typing import List, Dict
import enum
from dataclasses import dataclass, field
from dataclasses_json import dataclass_json, config
from collections import defaultdict
import logging

PORT = 3356

@dataclass_json
@dataclass(frozen=True)
class Team:
    name: str
    hostname: str

@dataclass_json
@dataclass(frozen=True)
class Service:
    name: str
    port: int

@dataclass_json
@dataclass(frozen=True)
class Target:
    team: Team
    service: Service
    flag_id: str

    def same_process(self, other: 'Target'):
        return self.team == other.team and self.service == other.service

class SubmissionResult(enum.Enum):
    OK = 'OK'
    INVALID = 'INVALID'
    UNKNOWN = 'UNKNOWN'
    TOO_OLD = 'TOO_OLD'
    SELF = 'SELF'
    ALREADY_SUBMITTED = 'ALREADY_SUBMITTED'

@dataclass_json
@dataclass(frozen=True)
class Submission:
    flag: bytes = field(metadata=config(encoder=lambda b: b.decode('latin-1'), decoder=lambda s: s.encode('latin-1')))
    target: Target
    script: str

@dataclass
class SubmissionLog:
    submission: Submission
    result: SubmissionResult

@dataclass_json
@dataclass
class ScriptProgress:
    runs: int = 0

@dataclass_json
@dataclass
class TargetStatus:
    tick_first_seen: int
    tick_last_seen: int
    script_status: Dict[str, ScriptProgress] = field(default_factory=lambda: defaultdict(ScriptProgress))
    retired: bool = False

@dataclass
class GameStatus:
    tick: int
    targets: List[Target]

@dataclass_json
@dataclass
class ScriptStatus:
    filename: str
    service_name: str
    tick_first_seen: int
    tick_last_seen: int

@dataclass_json
@dataclass
class ShooterStatus:
    tick: int
    targets: Dict[Target, TargetStatus] = field(metadata=config(
        encoder=lambda d: [{"target": t.to_dict(), "status": s.to_dict()} for t, s in d.items()],
        decoder=lambda l: {Target.from_dict(e['target']): TargetStatus.from_dict(e['status']) for e in l},
    ))
    script_info: Dict[str, ScriptStatus]  # keyed on hash
    tick_timeout: int
    retry_timeout: int

def setup_logging():
    """installs logging configuration. run this before any other code"""
    # TODO: also send the logs to visualizer
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    fm = logging.Formatter(
        "%(asctime)s - %(name)-25s - %(funcName)-10s - %(levelname)-5s"
        + " - %(message)s")
    ch.setFormatter(fm)
    root.addHandler(ch)
