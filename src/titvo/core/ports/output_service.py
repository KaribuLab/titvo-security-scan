from abc import ABC, abstractmethod
from titvo.app.scan.scan_entities import ScanResult
from titvo.app.task.task_entities import TaskSource

class OutputService(ABC):
    @abstractmethod
    def execute(self, scan_result: ScanResult) -> dict:
        pass


class OutputServiceFactory(ABC):
    @abstractmethod
    def create_output_service(self, source: TaskSource) -> OutputService:
        pass
