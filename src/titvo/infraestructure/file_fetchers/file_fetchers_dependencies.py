from dataclasses import dataclass
from titvo.core.ports.configuration_service import ConfigurationService
from titvo.core.ports.storage_service import StorageService
from titvo.core.ports.cli_files_repository import CliFilesRepository
from titvo.infraestructure.file_fetchers.file_fetcher_factory import (
    FileFetcherServiceFactoryImpl,
)


@dataclass
class FileFetchersDependencies:
    file_fetcher_service_factory: FileFetcherServiceFactoryImpl


def get_dependencies(
    configuration_service: ConfigurationService,
    storage_service: StorageService,
    cli_files_repository: CliFilesRepository,
    cli_files_bucket_name: str,
    repo_files_path: str,
) -> FileFetchersDependencies:
    return FileFetchersDependencies(
        file_fetcher_service_factory=FileFetcherServiceFactoryImpl(
            configuration_service=configuration_service,
            storage_service=storage_service,
            cli_files_repository=cli_files_repository,
            cli_files_bucket_name=cli_files_bucket_name,
            repo_files_path=repo_files_path,
        ),
    )
