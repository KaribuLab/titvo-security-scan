from titvo.core.ports.ai_provider import AIProvider
from titvo.app.scan.scan_entities import Prompt, ScanResult


class AnthropicProvider(AIProvider):
    def execute(self, prompt: Prompt) -> ScanResult:
        pass
