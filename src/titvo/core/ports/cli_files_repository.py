from abc import ABC, abstractmethod
from typing import List
from titvo.app.cli_files.cli_files_entities import CliFiles
class CliFilesRepository(ABC):
    @abstractmethod
    def get_files(self, batch_id: str) -> List[CliFiles]:
        pass
