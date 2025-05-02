import os
import base64
from typing import List
from dataclasses import dataclass
from github import Github
from titvo.core.ports.file_fetcher_service import FileFetcherService
from titvo.core.ports.configuration_service import ConfigurationService


@dataclass
class GithubFileFetcherServiceArgs:
    github_token: str
    github_repo_name: str
    github_commit_sha: str
    github_assignee: str


class GithubFileFetcherService(FileFetcherService):
    def __init__(
        self,
        args: GithubFileFetcherServiceArgs,
        configuration_service: ConfigurationService,
        repo_files_path: str,
    ):
        self.args = args
        self.configuration_service = configuration_service
        self.repo_files_path = repo_files_path
        self.access_token = self.configuration_service.decrypt(self.args.github_token)
        self.github_instance = Github(self.access_token)

    def fetch_files(self) -> List[str]:
        repo = self.github_instance.get_repo(self.args.github_repo_name)
        commit = repo.get_commit(self.args.github_commit_sha)
        os.makedirs(self.repo_files_path, exist_ok=True)
        for file in commit.files:
            content = repo.get_contents(file.filename, ref=self.args.github_commit_sha)
            os.makedirs(
                os.path.dirname(os.path.join(self.repo_files_path, file.filename)),
                exist_ok=True,
            )

            if isinstance(content.content, str):
                file_content = base64.b64decode(content.content).decode("utf-8")
            else:
                file_content = content.decoded_content.decode("utf-8")

            with open(
                os.path.join(self.repo_files_path, file.filename), "w", encoding="utf-8"
            ) as f:
                f.write(file_content)
        return [file.filename for file in commit.files]
