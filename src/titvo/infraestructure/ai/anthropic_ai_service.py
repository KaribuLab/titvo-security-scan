from langchain_anthropic import ChatAnthropic

from titvo.infraestructure.ai.base_ai_service import BaseAiService


class AnthropicAiService(BaseAiService):
    def _create_llm(self):
        api_key = self.configuration_service.get_secret("anthropic_api_key")
        model = self.configuration_service.get_value("anthropic_model")
        return ChatAnthropic(model=model, api_key=api_key, max_retries=3)
