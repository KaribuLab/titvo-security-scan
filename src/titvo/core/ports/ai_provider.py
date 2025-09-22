from abc import ABC, abstractmethod
from titvo.app.scan.scan_entities import Prompt, ScanResult


class AIProvider(ABC):

    def __init__(self, provider_api_key: str, provider_model: str):
        self.provider_api_key = provider_api_key
        self.provider_model = provider_model

    @abstractmethod
    def execute(self, prompt: Prompt) -> ScanResult:
        pass
