from dataclasses import dataclass

from titvo.core.ports.ai_service import AiService
from titvo.core.ports.configuration_service import ConfigurationService
from titvo.infraestructure.ai.ai_service_factory import create_ai_service


@dataclass
class AiDependencies:
    ai_service: AiService


def get_dependencies(configuration_service: ConfigurationService) -> AiDependencies:
    return AiDependencies(ai_service=create_ai_service(configuration_service))
