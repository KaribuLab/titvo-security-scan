from titvo.core.ports.ai_provider import AIProvider
from titvo.core.ports.configuration_service import ConfigurationService
from titvo.infraestructure.ai.openai_provider import OpenAIProvider
from titvo.infraestructure.ai.anthropic_provider import AnthropicProvider


class IAProviderFactory:
    def __init__(self, configuration_service: ConfigurationService):
        self.configuration_service = configuration_service

    def get_ai_provider(self, provider: str) -> AIProvider:
        provider_api_key = self.configuration_service.get_secret("provider_api_key")
        provider_model = self.configuration_service.get_value("provider_model")
        if provider == "openai":
            return OpenAIProvider(
                provider_api_key=provider_api_key,
                provider_model=provider_model,
            )
        elif provider == "anthropic":
            return AnthropicProvider(
                provider_api_key=provider_api_key,
                provider_model=provider_model,
            )
        raise ValueError(f"Provider {provider} not supported")
