import logging
from abc import abstractmethod

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.runnables import RunnableConfig

from titvo.app.scan.scan_entities import Annotation, Prompt, ScanResult, ScanStatus
from titvo.core.ports.ai_service import AiService
from titvo.core.ports.configuration_service import ConfigurationService
from titvo.infraestructure.ai.report_annotation import ReportAnnotation

LOGGER = logging.getLogger(__name__)


class BaseAiService(AiService):
    def __init__(self, configuration_service: ConfigurationService):
        self.configuration_service = configuration_service

    @abstractmethod
    def _create_llm(self) -> BaseChatModel:
        pass

    def execute(self, prompt: Prompt) -> ScanResult:
        llm = self._create_llm()
        config = RunnableConfig(
            tags=["security-scan"],
            metadata={"purpose": "chunked-analysis"},
            max_concurrency=5,
        )
        inputs = []
        for user_prompt in prompt.user_prompts:
            messages = [
                SystemMessage(content=prompt.system_prompt),
                HumanMessage(content=f"{user_prompt}\n\njson"),
            ]
            inputs.append(messages)
        structured_llm = llm.with_structured_output(ReportAnnotation)
        outputs = structured_llm.batch(inputs, config=config)
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
