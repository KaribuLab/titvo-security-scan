from dataclasses import dataclass
from titvo.core.ports.configuration_service import ConfigurationService
from titvo.infraestructure.ai.ai_factory import IAProviderFactory


@dataclass
class AiDependencies:
    ai_provider_factory: IAProviderFactory


def get_dependencies(configuration_service: ConfigurationService) -> AiDependencies:
    return AiDependencies(ai_provider_factory=IAProviderFactory(configuration_service))
