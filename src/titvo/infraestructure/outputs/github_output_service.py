from dataclasses import dataclass
import logging
from github import Github
from titvo.core.ports.output_service import OutputService, OutputResult
from titvo.core.ports.configuration_service import ConfigurationService
from titvo.app.scan.scan_entities import ScanResult

LOGGER = logging.getLogger(__name__)


@dataclass
class GithubOutputArgs:
    github_token: str
    github_repo_name: str
    github_commit_sha: str
    github_assignee: str


@dataclass
class GithubOutputResult(OutputResult):
    issue_url: str

    def to_dict(self) -> dict:
        return {
            "issue_url": self.issue_url,
        }


class GithubOutputService(OutputService):
    def __init__(
        self,
        args: GithubOutputArgs,
        configuration_service: ConfigurationService,
    ):
        self.args = args
        self.configuration_service = configuration_service
        self.access_token = self.configuration_service.decrypt(self.args.github_token)
        self.github_instance = Github(self.access_token)

    def execute(self, scan_result: ScanResult) -> OutputResult:
        repo = self.github_instance.get_repo(self.args.github_repo_name)
        commit = repo.get_commit(self.args.github_commit_sha)
        title = f"[BUG] Problema de seguridad en el commit {self.args.github_commit_sha[:7]}"
        body = (
            f"# 🐛 Problema de seguridad detectado\n\n"
            f"**Commit:** {self.args.github_commit_sha}\n"
            f"**Autor:** {commit.commit.author.name}\n\n"
            f"## Resultados del análisis\n\n"
        )
        issue_number = 0
        for annotation in scan_result.annotations:
            issue_number += 1
            body += f"""\n
## {issue_number}. {annotation.title}
**Severidad:** {annotation.severity}

## Descripción del problema
{annotation.description}

## Ubicación exacta (archivo y línea)
{annotation.path} - (línea {annotation.line})

```
{annotation.code}
```

### Recomandaciones para solucionar el problema
{annotation.recommendation}
"""
        issue = repo.create_issue(title=title, body=body, labels=["bug"])
        if self.args.github_assignee:
            LOGGER.info(
                "Asignando issue al usuario configurado: %s", self.args.github_assignee
            )
            # Asignar el issue
            issue.add_to_assignees(self.args.github_assignee)
            LOGGER.info("Issue asignado a %s", self.args.github_assignee)
        return GithubOutputResult(
            issue_url=issue.html_url,
        )
