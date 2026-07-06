from titvo.core.ports.ai_service import AiService
from titvo.core.ports.configuration_service import ConfigurationService
from titvo.infraestructure.ai.anthropic_ai_service import AnthropicAiService
from titvo.infraestructure.ai.google_ai_service import GoogleAiService
from titvo.infraestructure.ai.open_router_ai_service import OpenRouterAiService
from titvo.infraestructure.ai.openai_ai_service import OpenAIAiService


def create_ai_service(configuration_service: ConfigurationService) -> AiService:
    provider = configuration_service.get_value("ai_provider").lower().strip()
    if provider == "openai":
        return OpenAIAiService(configuration_service)
    elif provider == "anthropic":
        return AnthropicAiService(configuration_service)
    elif provider == "google":
        return GoogleAiService(configuration_service)
    elif provider == "openrouter":
        return OpenRouterAiService(configuration_service)
    else:
        raise ValueError(f"Unsupported AI provider: {provider}")
