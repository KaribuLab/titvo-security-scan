from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional

@dataclass
class DownloadFileRequest:
    container_name: str
    file_path: str
    output_path: str


@dataclass
class UploadFileRequest:
    container_name: str
    input_path: str
    file_path: str
    content_type: Optional[str] = None


class StorageService(ABC):
    @abstractmethod
    def download_file(self, request: DownloadFileRequest) -> None:
        pass

    @abstractmethod
    def upload_file(self, request: UploadFileRequest) -> None:
        pass
