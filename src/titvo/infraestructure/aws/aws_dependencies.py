from dataclasses import dataclass
from titvo.infraestructure.aws.dynamo_task_repository import DynamoTaskRepository
from titvo.infraestructure.aws.dynamo_configuration_service import (
    DynamoConfigurationService,
)
from titvo.infraestructure.aws.s3_storage_service import S3StorageService
from titvo.infraestructure.aws.dynamo_hint_repository import DynamoHintRepository
from titvo.infraestructure.aws.dynamo_cli_files_repository import (
    DynamoCliFilesRepository,
)

@dataclass
class AwsDependencies:
    task_repository: DynamoTaskRepository
    configuration_service: DynamoConfigurationService
    storage_service: S3StorageService
    hint_repository: DynamoHintRepository
    cli_files_repository: DynamoCliFilesRepository


def get_dependencies(
    dynamo_task_table_name: str,
    dynamo_configuration_table_name: str,
    dynamo_hint_table_name: str,
    encryption_key_name: str,
    dynamo_cli_files_table_name: str,
) -> AwsDependencies:
    return AwsDependencies(
        task_repository=DynamoTaskRepository(table_name=dynamo_task_table_name),
        configuration_service=DynamoConfigurationService(
            table_name=dynamo_configuration_table_name,
            encryption_key_name=encryption_key_name,
        ),
        storage_service=S3StorageService(),
        hint_repository=DynamoHintRepository(table_name=dynamo_hint_table_name),
        cli_files_repository=DynamoCliFilesRepository(
            table_name=dynamo_cli_files_table_name
        ),
    )
