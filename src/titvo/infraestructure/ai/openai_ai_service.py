from typing import List, Literal
from pydantic import BaseModel, Field
from langchain.chat_models import init_chat_model
from langchain_core.messages import HumanMessage, SystemMessage
from titvo.core.ports.ai_service import AiService
from titvo.core.ports.configuration_service import ConfigurationService
from titvo.app.scan.scan_entities import Prompt, ScanResult, ScanStatus, Annotation


class ReportAnnotation(BaseModel):
    title: str = Field(
        ...,
        description="Título del issue encontrado. Siempre debe estar presente.",
    )
    description: str = Field(
        ...,
        description="Breve descripción del issue encontrado. Siempre debe estar presente.",
    )
    summary: str = Field(
        ...,
        description="Breve resumen del issue en menos de 400 caracteres. Siempre debe estar presente.",
    )
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"] = Field(
        ..., description="Nivel de severidad del issue. Siempre debe estar presente."
    )
    path: str = Field(
        ...,
        description="Ruta del archivo donde se encontró el issue. Siempre debe estar presente.",
    )
    line: int = Field(
        ...,
        ge=1,
        description="Primera línea del archivo donde se encontró el issue. Siempre debe estar presente.",
    )
    code: str = Field(
        ...,
        description="Fragmento de código donde se encontró el issue. Siempre debe estar presente.",
    )
    recommendation: str = Field(
        ...,
        description="Recomendación para corregir el issue. Siempre debe estar presente.",
    )


class SecurityReport(BaseModel):
    status: Literal["FAILED", "WARNING", "SUCCESS"] = Field(
        ...,
        description="FAILED: al menos un issue CRITICAL, HIGH o MEDIUM. "
        "WARNING: solo issues LOW. "
        "SUCCESS: ningún issue CRITICAL, HIGH, MEDIUM o LOW. Siempre debe estar presente.",
    )
    number_of_issues: int = Field(
        ...,
        ge=0,
        description="Número total de issues encontrados. Siempre debe estar presente.",
    )
    annotations: List[ReportAnnotation] = Field(
        ..., description="Lista de issues encontrados. Siempre debe estar presente."
    )


class OpenAIAiService(AiService):
    def __init__(self, configuration_service: ConfigurationService):
        self.configuration_service = configuration_service

    def execute(self, prompt: Prompt) -> ScanResult:
        openai_api_key = self.configuration_service.get_secret("open_ai_api_key")
        model = self.configuration_service.get_value("open_ai_model")
        llm = init_chat_model(model, model_provider="openai", api_key=openai_api_key)
        structured_llm = llm.with_structured_output(
            SecurityReport,
            method="json_mode",
        )
        output = structured_llm.invoke(
            [
                SystemMessage(content=prompt.system_prompt),
                HumanMessage(
                    content=f"{prompt.user_prompt}\nIncluye todos los campos de la estructa JSON"
                ),
            ]
        )
        return ScanResult(
            annotations=[
                Annotation(
                    title=annotation.title,
                    description=annotation.description,
                    severity=annotation.severity,
                    path=annotation.path,
                    line=annotation.line,
                    summary=annotation.summary,
                    code=annotation.code,
                    recommendation=annotation.recommendation,
                )
                for annotation in output.annotations
            ],
            number_of_issues=output.number_of_issues,
            status=ScanStatus(output.status),
        )
