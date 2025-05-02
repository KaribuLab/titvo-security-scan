from dataclasses import dataclass
from titvo.core.ports.configuration_service import ConfigurationService
from titvo.infraestructure.ai.openai_ai_service import OpenAIAiService


@dataclass
class AiDependencies:
    ai_service: OpenAIAiService


def get_dependencies(configuration_service: ConfigurationService) -> AiDependencies:
    return AiDependencies(ai_service=OpenAIAiService(configuration_service))
