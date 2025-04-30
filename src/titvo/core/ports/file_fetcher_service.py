from abc import ABC, abstractmethod
from typing import List
from titvo.app.task.task_entities import TaskSource


class FileFetcherService(ABC):
    @abstractmethod
    def fetch_files(self) -> List[str]:
        pass


class FileFetcherServiceFactory(ABC):
    @abstractmethod
    def create_file_fetcher_service(
        self, args: dict, source: TaskSource
    ) -> FileFetcherService:
        pass
