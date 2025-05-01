from titvo.core.ports.configuration_service import ConfigurationService
from titvo.core.ports.output_service import OutputService, OutputServiceFactory
from titvo.app.task.task_entities import TaskSource
from titvo.infraestructure.outputs.bitbucket_output_service import (
    BitbucketOutputService,
    BitbucketOutputArgs,
)
from titvo.infraestructure.outputs.github_output_service import (
    GithubOutputService,
    GithubOutputArgs,
)
from titvo.infraestructure.outputs.cli_output_service import (
    CliOutputService,
    CliOutputArgs,
)
from titvo.core.ports.storage_service import StorageService


class OutputsServiceFactoryImpl(OutputServiceFactory):
    def __init__(
        self,
        configuration_service: ConfigurationService,
        storage_service: StorageService,
        template_path: str,
    ):
        self.configuration_service = configuration_service
        self.storage_service = storage_service
        self.template_path = template_path

    def create_output_service(
        self, args: dict, scan_id: str, source: TaskSource
    ) -> OutputService:
        if source == TaskSource.BITBUCKET:
            return BitbucketOutputService(
                args=BitbucketOutputArgs(**args),
                configuration_service=self.configuration_service,
                storage_service=self.storage_service,
                template_path=self.template_path,
                scan_id=scan_id,
                source=source,
            )
        elif source == TaskSource.GITHUB:
            return GithubOutputService(
                args=GithubOutputArgs(**args),
                configuration_service=self.configuration_service,
            )
        elif source == TaskSource.CLI:
            return CliOutputService(
                args=CliOutputArgs(**args),
                configuration_service=self.configuration_service,
                storage_service=self.storage_service,
                template_path=self.template_path,
                scan_id=scan_id,
                source=source,
            )
