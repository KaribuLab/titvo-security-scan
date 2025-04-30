import logging
import os
import tarfile
from typing import List
from dataclasses import dataclass
from titvo.core.ports.cli_files_repository import CliFilesRepository
from titvo.core.ports.configuration_service import ConfigurationService
from titvo.core.ports.file_fetcher_service import FileFetcherService
from titvo.core.ports.storage_service import StorageService, DownloadFileRequest

# Disable logging
logging.getLogger("boto3").setLevel(logging.WARNING)
logging.getLogger("botocore").setLevel(logging.WARNING)
logging.getLogger("moto").setLevel(logging.WARNING)
logging.getLogger("s3transfer").setLevel(logging.WARNING)

@dataclass
class CliFileFetcherServiceArgs:
    batch_id: str
    repository_slug: str


class CliFileFetcherService(FileFetcherService):
    def __init__(
        self,
        args: CliFileFetcherServiceArgs,
        configuration_service: ConfigurationService,
        storage_service: StorageService,
        cli_files_repository: CliFilesRepository,
        cli_files_bucket_name: str,
        repo_files_path: str,
    ):
        self.args = args
        self.configuration_service = configuration_service
        self.storage_service = storage_service
        self.cli_files_repository = cli_files_repository
        self.cli_files_bucket_name = cli_files_bucket_name
        self.repo_files_path = repo_files_path

    def fetch_files(self) -> List[str]:
        os.makedirs(self.repo_files_path, exist_ok=True)
        cli_files = self.cli_files_repository.get_files(self.args.batch_id)
        extracted_files = []
        for cli_file in cli_files:
            file_key = cli_file.file_key
            self.storage_service.download_file(
                DownloadFileRequest(
                    container_name=self.cli_files_bucket_name,
                    file_path=file_key,
                    output_path=os.path.join(self.repo_files_path, file_key),
                )
            )
            tgz_path = os.path.join(self.repo_files_path, file_key)
            with tarfile.open(tgz_path, "r:gz") as tar:
                tar.extractall(path=self.repo_files_path)
                for member in tar.getmembers():
                    extracted_files.append(member.name)
            os.remove(tgz_path)
        return extracted_files
