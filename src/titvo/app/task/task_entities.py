from dataclasses import dataclass
from enum import Enum
from datetime import datetime


class TaskSource(Enum):
    GITHUB = "github"
    BITBUCKET = "bitbucket"
    CLI = "cli"


class TaskStatus(Enum):
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    ERROR = "ERROR"


@dataclass
class Task:
    id: str
    result: dict
    args: dict
    hint_id: str
    scaned_files: int
    created_at: datetime
    updated_at: datetime
    status: TaskStatus
    source: TaskSource

    def mark_in_progress(self):
        self.status = TaskStatus.IN_PROGRESS
        self.updated_at = datetime.now()

    def mark_completed(self, result: dict, scaned_files: int):
        self.status = TaskStatus.COMPLETED
        self.result = result
        self.scaned_files = scaned_files
        self.updated_at = datetime.now()

    def mark_failed(self, result: dict, scaned_files: int):
        self.status = TaskStatus.FAILED
        self.result = result
        self.scaned_files = scaned_files
        self.updated_at = datetime.now()

    def mark_error(self):
        self.status = TaskStatus.ERROR
        self.updated_at = datetime.now()
