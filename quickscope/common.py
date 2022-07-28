from typing import List, Dict
import enum
from dataclasses import dataclass, field
from collections import defaultdict
import json

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

@dataclass(frozen=True)
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
