import boto3
from titvo.core.ports.storage_service import (
    StorageService,
    DownloadFileRequest,
    UploadFileRequest,
)


class S3StorageService(StorageService):

    def __init__(self):
        self.s3_client = boto3.client("s3")

    def download_file(self, request: DownloadFileRequest) -> None:
        return self.s3_client.download_file(
            request.container_name, request.file_path, request.output_path
        )

    def upload_file(self, request: UploadFileRequest) -> None:
        return self.s3_client.upload_file(
            request.input_path, request.container_name, request.file_path
        )
