from abc import ABC, abstractmethod
from titvo.app.scan.scan_entities import ScanResult


class OutputService(ABC):
    @abstractmethod
    def execute(self, scan_result: ScanResult) -> dict:
        pass


class OutputServiceFactory(ABC):
    @abstractmethod
    def get_output_service(self, source: str) -> OutputService:
        pass
