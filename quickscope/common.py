from typing import List, Dict, Optional
import enum
from dataclasses import dataclass, field
from dataclasses_json import config, DataClassJsonMixin
from collections import defaultdict
import logging

PORT = 3356

@dataclass(frozen=True)
class Team(DataClassJsonMixin):
    name: str
    hostname: str

@dataclass(frozen=True)
class Service(DataClassJsonMixin):
    name: str
    port: int

@dataclass(frozen=True)
class Target(DataClassJsonMixin):
    team: Team
    service: Service
    flag_id: str
    tick: Optional[int] = None

    def same_process(self, other: 'Target'):
        return self.team == other.team and self.service == other.service

class SubmissionResult(enum.Enum):
    OK = 'OK'
    INVALID = 'INVALID'
    UNKNOWN = 'UNKNOWN'
    TOO_OLD = 'TOO_OLD'
    SELF = 'SELF'
    ALREADY_SUBMITTED = 'ALREADY_SUBMITTED'

@dataclass(frozen=True)
class Submission(DataClassJsonMixin):
    flag: bytes = field(metadata=config(encoder=lambda b: b.decode('latin-1'), decoder=lambda s: s.encode('latin-1')))
    target: Target
    script: str

@dataclass
class SubmissionLog:
    submission: Submission
    result: SubmissionResult

@dataclass
class ScriptProgress(DataClassJsonMixin):
    runs: int = 0

@dataclass
class TargetStatus(DataClassJsonMixin):
    tick_first_seen: int
    tick_last_seen: int
    script_status: Dict[str, ScriptProgress] = field(default_factory=lambda: defaultdict(ScriptProgress))
    retired: bool = False

@dataclass
class GameStatus:
    tick: int
    targets: List[Target]

@dataclass
class ScriptStatus(DataClassJsonMixin):
    filename: str
    service_name: str
    tick_first_seen: int
    tick_last_seen: int

@dataclass
class ShooterStatus(DataClassJsonMixin):
    tick: int
    targets: Dict[Target, TargetStatus] = field(metadata=config(
        encoder=lambda d: [{"target": t.to_dict(), "status": s.to_dict()} for t, s in d.items()],
        decoder=lambda l: {Target.from_dict(e['target']): TargetStatus.from_dict(e['status']) for e in l},
    ))
    script_info: Dict[str, ScriptStatus]  # keyed on hash
    tick_timeout: int
    retry_timeout: int
    error_log: str

def setup_logging():
    """installs logging configuration. run this before any other code"""
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    logging.getLogger('quickscope').setLevel('DEBUG')
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    fm = logging.Formatter(
        "%(asctime)s - %(name)-25s - %(funcName)-10s - %(levelname)-5s"
        + " - %(message)s")
    ch.setFormatter(fm)
    root.addHandler(ch)
