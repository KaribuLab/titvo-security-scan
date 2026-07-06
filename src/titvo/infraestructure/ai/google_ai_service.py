from langchain_google_genai import ChatGoogleGenerativeAI

from titvo.infraestructure.ai.base_ai_service import BaseAiService


class GoogleAiService(BaseAiService):
    def _create_llm(self):
        api_key = self.configuration_service.get_secret("google_api_key")
        model = self.configuration_service.get_value("google_model")
        return ChatGoogleGenerativeAI(model=model, google_api_key=api_key, max_retries=3)
