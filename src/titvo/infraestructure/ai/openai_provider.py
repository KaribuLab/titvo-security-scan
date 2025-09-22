from typing import Literal
import logging
from pydantic import BaseModel, Field
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.runnables import RunnableConfig
from langchain_openai import ChatOpenAI
from titvo.core.ports.ai_provider import AIProvider
from titvo.app.scan.scan_entities import Prompt, ScanResult, ScanStatus, Annotation

LOGGER = logging.getLogger(__name__)


class ReportAnnotation(BaseModel):
    title: str = Field(
        ...,
        description=(
            "Título del issue encontrado. Siempre debe estar presente. "
            "Si el issue es de tipo NONE, no debe estar presente."
        ),
    )
    description: str = Field(
        ...,
        description=(
            "Breve descripción del issue encontrado. "
            "Si el issue es de tipo NONE, no debe estar presente."
        ),
    )
    summary: str = Field(
        ...,
        description=(
            "Breve resumen del issue en menos de 400 caracteres. "
            "Si el issue es de tipo NONE, no debe estar presente."
        ),
    )
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"] = Field(
        ...,
        description=(
            "Nivel de severidad del issue. Siempre debe estar presente. "
            "Si el issue es de tipo NONE, no debe estar presente."
        ),
    )
    path: str = Field(
        ...,
        description="Ruta del archivo donde se encontró el issue. Siempre debe estar presente.",
    )
    line: int = Field(
        ...,
        description=(
            "Primera línea del archivo donde se encontró el issue. "
            "Si el issue es de tipo NONE, no debe estar presente."
        ),
        ge=0,
    )
    code: str = Field(
        ...,
        description=(
            "Fragmento de código donde se encontró el issue. "
            "Si el issue es de tipo NONE, no debe estar presente."
        ),
    )
    recommendation: str = Field(
        ...,
        description=(
            "Recomendación para corregir el issue. "
            "Si el issue es de tipo NONE, no debe estar presente."
        ),
    )


class OpenAIProvider(AIProvider):

    def execute(self, prompt: Prompt) -> ScanResult:
        llm = ChatOpenAI(
            model=self.provider_model,
            api_key=self.provider_api_key,
            max_retries=3,
            seed=42,
        )
        config = RunnableConfig(
            tags=["security-scan"],
            metadata={"purpose": "chunked-analysis"},
            max_concurrency=5,
        )
        inputs = []
        for user_prompt in prompt.user_prompts:
            # pylint: disable=redefined-builtin
            input = [
                SystemMessage(content=prompt.system_prompt),
                HumanMessage(content=f"{user_prompt}\n\njson"),
            ]
            # pylint: enable=redefined-builtin
            inputs.append(input)
        structured_llm = llm.with_structured_output(
            ReportAnnotation,
            method="json_mode",
        )
        outputs = outputs = structured_llm.batch(inputs, config=config)
        annotations = []
        number_of_issues = 0
        status = ScanStatus.SUCCESS
        medium_issues = 0
        low_issues = 0
        high_issues = 0
        critical_issues = 0
        for output in outputs:
            if output.severity != "NONE":
                annotations.append(
                    Annotation(
                        title=output.title,
                        description=output.description,
                        severity=output.severity,
                        path=output.path,
                        line=output.line,
                        summary=output.summary,
                        code=output.code,
                        recommendation=output.recommendation,
                    )
                )
                number_of_issues += 1
                if output.severity == "LOW":
                    low_issues += 1
                elif output.severity == "MEDIUM":
                    medium_issues += 1
                elif output.severity == "HIGH":
                    high_issues += 1
                elif output.severity == "CRITICAL":
                    critical_issues += 1
        if critical_issues > 0 or high_issues > 0:
            status = ScanStatus.FAILED
        elif medium_issues > 0 or low_issues > 0:
            status = ScanStatus.WARNING
        else:
            status = ScanStatus.SUCCESS
        return ScanResult(
            annotations=annotations,
            number_of_issues=number_of_issues,
            status=status,
        )
