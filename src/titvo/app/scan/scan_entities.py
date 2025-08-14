from dataclasses import dataclass, asdict
from enum import Enum
from typing import List


class ScanStatus(Enum):
    SUCCESS = "SUCCESS"
    WARNING = "WARNING"
    FAILED = "FAILED"

@dataclass
class Scan:
    id: str


@dataclass
class Prompt:
    system_prompt: str
    user_prompts: list[str]


@dataclass
class Annotation:
    title: str
    description: str
    severity: str
    path: str
    line: int
    summary: str
    code: str
    recommendation: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScanResult:
    status: ScanStatus
    number_of_issues: int
    annotations: List[Annotation]

    def to_dict(self) -> dict:
        return {
            'status': self.status.value,
            'number_of_issues': self.number_of_issues,
            'annotations': [annotation.to_dict() for annotation in self.annotations]
        }
