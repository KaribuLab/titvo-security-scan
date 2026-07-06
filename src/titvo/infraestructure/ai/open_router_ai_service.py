from langchain_openai import ChatOpenAI

from titvo.infraestructure.ai.base_ai_service import BaseAiService


class OpenRouterAiService(BaseAiService):
    def _create_llm(self):
        api_key = self.configuration_service.get_secret("open_router_api_key")
        model = self.configuration_service.get_value("open_router_model")
        return ChatOpenAI(
            model=model,
            api_key=api_key,
            base_url="https://openrouter.ai/api/v1",
            max_retries=3,
        )
