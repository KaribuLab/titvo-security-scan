from dataclasses import dataclass
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
    user_prompt: str


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


@dataclass
class ScanResult:
    status: ScanStatus
    number_of_issues: int
    annotations: List[Annotation]
