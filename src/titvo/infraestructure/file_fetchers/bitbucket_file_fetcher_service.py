import os
from typing import List
from dataclasses import dataclass
import json
import requests
from titvo.core.ports.configuration_service import ConfigurationService
from titvo.core.ports.file_fetcher_service import FileFetcherService

ACCESS_TOKEN_URL = "https://bitbucket.org/site/oauth2/access_token"
BITBUCKET_API_URL = "https://api.bitbucket.org/2.0"


@dataclass
class BitbucketFileFetcherServiceArgs:
    bitbucket_repo_slug: str
    bitbucket_workspace: str
    bitbucket_project_key: str
    bitbucket_commit: str


class BitbucketFileFetcherService(FileFetcherService):
    def __init__(
        self,
        args: BitbucketFileFetcherServiceArgs,
        configuration_service: ConfigurationService,
        repo_files_path: str,
    ):
        self.args = args
        self.configuration_service = configuration_service
        self.repo_files_path = repo_files_path

    def fetch_files(self) -> List[str]:
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
        commit_url = (
            f"{BITBUCKET_API_URL}/repositories/{self.args.bitbucket_workspace}/"
            f"{self.args.bitbucket_repo_slug}/commit/{self.args.bitbucket_commit}"
        )
        commit_response = requests.get(commit_url, headers=headers, timeout=30)
        commit_response.raise_for_status()
        commit_info = commit_response.json()
        commit_hash = commit_info.get("hash")
        diff_url = (
            f"{BITBUCKET_API_URL}/repositories/{self.args.bitbucket_workspace}/"
            f"{self.args.bitbucket_repo_slug}/diff/{self.args.bitbucket_commit}"
        )
        diff_response = requests.get(diff_url, headers=headers, timeout=30)
        diff_response.raise_for_status()
        diff_content = diff_response.text
        files = []
        for line in diff_content.split("\n"):
            if line.startswith("diff --git"):
                file_path = line.split(" b/")[1]
                files.append(file_path)
                content_url = (
                    f"{BITBUCKET_API_URL}/repositories/{self.args.bitbucket_workspace}/"
                    f"{self.args.bitbucket_repo_slug}/src/{commit_hash}/{file_path}"
                )
                response = requests.get(content_url, headers=headers, timeout=30)
                response.raise_for_status()
                full_path = os.path.join(self.repo_files_path, file_path)
                dirname = os.path.dirname(full_path)
                if dirname != "":
                    os.makedirs(dirname, exist_ok=True)
                with open(full_path, "w", encoding="utf-8") as f:
                    f.write(response.text)
        return files
