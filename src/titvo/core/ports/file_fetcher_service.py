from abc import ABC, abstractmethod
from typing import List


class FileFetcherService(ABC):
    @abstractmethod
    def fetch_files(self) -> List[str]:
        pass

class FileFetcherServiceFactory(ABC):
    @abstractmethod
    def create_file_fetcher_service(self, source: str) -> FileFetcherService:
        pass
