import os
from dataclasses import dataclass
from titvo.core.ports.output_service import OutputService, OutputResult
from titvo.core.ports.configuration_service import ConfigurationService
from titvo.core.ports.storage_service import StorageService, UploadFileRequest
from titvo.app.scan.scan_entities import ScanResult
from titvo.app.task.task_entities import TaskSource
from titvo.infraestructure.outputs.html_report import create_issue_html


@dataclass
class CliOutputArgs:
    batch_id: str
    repository_url: str


@dataclass
class CliOutputResult(OutputResult):
    report_url: str

    def to_dict(self) -> dict:
        return {
            "report_url": self.report_url,
        }


class CliOutputService(OutputService):
    def __init__(
        self,
        args: CliOutputArgs,
        configuration_service: ConfigurationService,
        storage_service: StorageService,
        template_path: str,
        scan_id: str,
        source: TaskSource,
    ):
        self.args = args
        self.configuration_service = configuration_service
        self.storage_service = storage_service
        self.template_path = template_path
        self.scan_id = scan_id
        self.source = source

    def execute(self, scan_result: ScanResult) -> OutputResult:
        os.makedirs(self.template_path, exist_ok=True)
        html_template_content = self.configuration_service.get_value(
            "report_html_template"
        )
        with open(
            os.path.join(self.template_path, "report.html"), "w", encoding="utf-8"
        ) as f:
            f.write(html_template_content)
        html_report_content = create_issue_html(
            scan_result,
            template_path=self.template_path,
            template_name="report.html",
        )
        html_report_name = f"{self.scan_id}.html"
        html_report_path = os.path.join(self.template_path, html_report_name)
        with open(html_report_path, "w", encoding="utf-8") as f:
            f.write(html_report_content)
        report_domain = self.configuration_service.get_value("report_bucket_domain")
        report_container_name = self.configuration_service.get_value(
            "report_bucket_name"
        )
        report_path = f"scm/{self.source.value}/scan/{self.scan_id}.html"
        self.storage_service.upload_file(
            UploadFileRequest(
                container_name=report_container_name,
                input_path=html_report_path,
                file_path=report_path,
                content_type="text/html; charset=utf-8",
            )
        )
        report_url = f"{report_domain}/{report_path}"
        return CliOutputResult(
            report_url=report_url,
        )
