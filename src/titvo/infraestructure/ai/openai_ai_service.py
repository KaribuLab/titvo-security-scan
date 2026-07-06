from langchain_openai import ChatOpenAI

from titvo.infraestructure.ai.base_ai_service import BaseAiService
from titvo.infraestructure.ai.report_annotation import ReportAnnotation  # noqa: F401


class OpenAIAiService(BaseAiService):
    def _create_llm(self):
        api_key = self.configuration_service.get_secret("open_ai_api_key")
        model = self.configuration_service.get_value("open_ai_model")
        return ChatOpenAI(model=model, api_key=api_key, max_retries=3, seed=42)
