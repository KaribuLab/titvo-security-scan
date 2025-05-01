from dataclasses import dataclass
import json
import uuid
import os
import requests
from titvo.core.ports.output_service import OutputService, OutputResult
from titvo.core.ports.configuration_service import ConfigurationService
from titvo.core.ports.storage_service import StorageService, UploadFileRequest
from titvo.app.scan.scan_entities import ScanResult, ScanStatus
from titvo.app.task.task_entities import TaskSource
from titvo.infraestructure.outputs.html_report import create_issue_html

ACCESS_TOKEN_URL = "https://bitbucket.org/site/oauth2/access_token"
BITBUCKET_API_URL = "https://api.bitbucket.org/2.0"


@dataclass
class BitbucketOutputArgs:
    bitbucket_workspace: str
    bitbucket_repo_slug: str
    bitbucket_commit: str


@dataclass
class BitbucketOutputResult(OutputResult):
    report_url: str

    def to_dict(self) -> dict:
        return {
            "report_url": self.report_url,
        }


class BitbucketOutputService(OutputService):
    def __init__(
        self,
        args: BitbucketOutputArgs,
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
        client_credentials = self.configuration_service.get_secret(
            "bitbucket_client_credentials"
        )
        if client_credentials is None:
            raise ValueError("Client credentials not found")
        credentials = json.loads(client_credentials)
        client_id = credentials.get("key")
        client_secret = credentials.get("secret")
        response = requests.post(
            ACCESS_TOKEN_URL,
            data={
                "client_id": client_id,
                "client_secret": client_secret,
                "grant_type": "client_credentials",
            },
            timeout=30,
        )
        response.raise_for_status()
        access_token = response.json().get("access_token")
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        }
        report_id = f"titvo-security-scan-{uuid.uuid4()}"
        base_url = f"{BITBUCKET_API_URL}/repositories/{self.args.bitbucket_workspace}"
        repo_path = (
            f"/{self.args.bitbucket_repo_slug}/commit/{self.args.bitbucket_commit}"
        )
        reports_path = "/reports/"
        create_report_url = f"{base_url}{repo_path}{reports_path}{report_id}"
        create_annotation_url = (
            f"{base_url}{repo_path}{reports_path}{report_id}/annotations"
        )
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
            )
        )
        report_url = f"{report_domain}/{report_path}"
        payload = {
            "title": "Titvo Security Scan",
            "details": "Security scan report",
            "report_type": "SECURITY",
            "reporter": "titvo-security-scan",
            "result": scan_result.status,
            "data": [
                {
                    "title": "Safe to merge?",
                    "type": "BOOLEAN",
                    "value": scan_result.status == ScanStatus.SUCCESS,
                },
                {
                    "title": "Number of issues",
                    "type": "NUMBER",
                    "value": scan_result.number_of_issues,
                },
                {
                    "title": "Report",
                    "type": "LINK",
                    "value": {"text": "See full report", "href": report_url},
                },
            ],
        }
        response = requests.put(
            create_report_url, headers=headers, json=payload, timeout=30
        )
        response.raise_for_status()
        payload = [
            {
                "external_id": f"{report_id}-annotation-{uuid.uuid4()}",
                "annotation_type": "VULNERABILITY",
                "title": item.title,
                "description": item.description,
                "severity": item.severity,
                "path": item.path,
                "line": item.line,
            }
            for item in scan_result.annotations
        ]
        response = requests.post(
            create_annotation_url,
            headers=headers,
            json=payload,
            timeout=30,
        )
        return BitbucketOutputResult(report_url=report_url)
