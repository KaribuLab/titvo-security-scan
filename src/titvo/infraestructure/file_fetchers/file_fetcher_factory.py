from titvo.app.task.task_entities import TaskSource
from titvo.core.ports.file_fetcher_service import (
    FileFetcherService,
    FileFetcherServiceFactory,
)
from titvo.infraestructure.file_fetchers.github_file_fetcher_service import (
    GithubFileFetcherService,
    GithubFileFetcherServiceArgs,
)
from titvo.infraestructure.file_fetchers.bitbucket_file_fetcher_service import (
    BitbucketFileFetcherService,
    BitbucketFileFetcherServiceArgs,
)
from titvo.infraestructure.file_fetchers.cli_file_fetcher_service import (
    CliFileFetcherService,
    CliFileFetcherServiceArgs,
)
from titvo.core.ports.configuration_service import ConfigurationService
from titvo.core.ports.storage_service import StorageService
from titvo.core.ports.cli_files_repository import CliFilesRepository


class FileFetcherServiceFactoryImpl(FileFetcherServiceFactory):
    def __init__(
        self,
        configuration_service: ConfigurationService,
        storage_service: StorageService,
        cli_files_repository: CliFilesRepository,
        cli_files_bucket_name: str,
        repo_files_path: str,
    ):
        self.configuration_service = configuration_service
        self.storage_service = storage_service
        self.cli_files_repository = cli_files_repository
        self.cli_files_bucket_name = cli_files_bucket_name
        self.repo_files_path = repo_files_path

    def create_file_fetcher_service(
        self, args: dict, source: TaskSource
    ) -> FileFetcherService:
        if source == TaskSource.GITHUB:
            if "github_token" not in args:
                raise ValueError("github_token is required")
            if "github_repo_name" not in args:
                raise ValueError("github_repo_name is required")
            if "github_commit_sha" not in args:
                raise ValueError("github_commit_sha is required")
            if "github_assignee" not in args:
                raise ValueError("github_assignee is required")
            return GithubFileFetcherService(
                GithubFileFetcherServiceArgs(
                    args["github_token"],
                    args["github_repo_name"],
                    args["github_commit_sha"],
                    args["github_assignee"],
                ),
                self.configuration_service,
                self.repo_files_path,
            )
        elif source == TaskSource.BITBUCKET:
            if "bitbucket_repo_slug" not in args:
                raise ValueError("bitbucket_repo_slug is required")
            if "bitbucket_workspace" not in args:
                raise ValueError("bitbucket_workspace is required")
            if "bitbucket_project_key" not in args:
                raise ValueError("bitbucket_project_key is required")
            if "bitbucket_commit" not in args:
                raise ValueError("bitbucket_commit is required")
            return BitbucketFileFetcherService(
                BitbucketFileFetcherServiceArgs(
                    args["bitbucket_repo_slug"],
                    args["bitbucket_workspace"],
                    args["bitbucket_project_key"],
                    args["bitbucket_commit"],
                ),
                self.configuration_service,
                self.repo_files_path,
            )
        elif source == TaskSource.CLI:
            if "batch_id" not in args:
                raise ValueError("batch_id is required")
            if "repository_slug" not in args:
                raise ValueError("repository_slug is required")
            return CliFileFetcherService(
                CliFileFetcherServiceArgs(
                    args["batch_id"],
                    args["repository_slug"],
                ),
                self.configuration_service,
                self.storage_service,
                self.cli_files_repository,
                self.cli_files_bucket_name,
                self.repo_files_path,
            )
