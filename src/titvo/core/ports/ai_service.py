from abc import ABC, abstractmethod
from titvo.app.scan.scan_entities import Prompt, ScanResult


class AiService(ABC):

    @abstractmethod
    def execute(self, prompt: Prompt) -> ScanResult:
        pass
