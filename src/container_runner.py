import os
import logging
from titvo.app.scan.scan_entities import Scan
from titvo.app.scan.scan_use_case import RunScanUseCase
from titvo.app.scan.scan_use_case import (
    GetTaskUseCase,
    MarkTaskInProgressUseCase,
    MarkTaskCompletedUseCase,
    MarkTaskFailedUseCase,
    MarkTaskErrorUseCase,
    GetHintUseCase,
)
from titvo.infraestructure.aws.aws_dependencies import (
    get_dependencies as get_aws_dependencies,
)
from titvo.infraestructure.ai.ia_dependencies import (
    get_dependencies as get_ai_dependencies,
)
from titvo.infraestructure.file_fetchers.file_fetchers_dependencies import (
    get_dependencies as get_file_fetchers_dependencies,
)
from titvo.infraestructure.outputs.outputs_dependencies import (
    get_dependencies as get_outputs_dependencies,
)

logging.getLogger("boto3").setLevel(logging.WARNING)
logging.getLogger("botocore").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
logging.getLogger("openai").setLevel(logging.WARNING)
logging.getLogger("httpx").setLevel(logging.WARNING)

logging.basicConfig(level=os.getenv("TITVO_LOG_LEVEL", "INFO"))

LOGGER = logging.getLogger(__name__)

AWS_INFRASTRUCTURE = "AWS"


def scan_from_container(task_id: str | None, infrastructure: str):
    LOGGER.info("Starting container runner")
    if task_id is None:
        raise ValueError("Task ID is not set")
    LOGGER.info("Task ID: %s", task_id)
    LOGGER.info("Infrastructure: %s", infrastructure)

    if infrastructure == AWS_INFRASTRUCTURE:
        LOGGER.info("Running AWS infrastructure")
        dynamo_task_table_name = os.getenv("TITVO_DYNAMO_TASK_TABLE_NAME")
        if not dynamo_task_table_name:
            raise ValueError("TITVO_DYNAMO_TASK_TABLE_NAME is not set")
        dynamo_configuration_table_name = os.getenv(
            "TITVO_DYNAMO_CONFIGURATION_TABLE_NAME"
        )
        if not dynamo_configuration_table_name:
            raise ValueError("TITVO_DYNAMO_CONFIGURATION_TABLE_NAME is not set")
        dynamo_hint_table_name = os.getenv("TITVO_DYNAMO_HINT_TABLE_NAME")
        if not dynamo_hint_table_name:
            raise ValueError("TITVO_DYNAMO_HINT_TABLE_NAME is not set")
        dynamo_cli_files_table_name = os.getenv("TITVO_DYNAMO_CLI_FILES_TABLE_NAME")
        if not dynamo_cli_files_table_name:
            raise ValueError("TITVO_DYNAMO_CLI_FILES_TABLE_NAME is not set")
        dynamo_cli_files_bucket_name = os.getenv("TITVO_DYNAMO_CLI_FILES_BUCKET_NAME")
        if not dynamo_cli_files_bucket_name:
            raise ValueError("TITVO_DYNAMO_CLI_FILES_BUCKET_NAME is not set")
        encryption_key_name = os.getenv("TITVO_ENCRYPTION_KEY_NAME")
        if not encryption_key_name:
            raise ValueError("TITVO_ENCRYPTION_KEY_NAME is not set")
        template_path = os.getenv("TITVO_TEMPLATE_PATH", "templates")
        repo_files_path = os.getenv("TITVO_REPO_FILES_PATH", "repo_files")
        LOGGER.debug("Repo files path: %s", repo_files_path)
        LOGGER.debug("Dynamo task table name: %s", dynamo_task_table_name)
        LOGGER.debug(
            "Dynamo configuration table name: %s", dynamo_configuration_table_name
        )
        LOGGER.debug("Dynamo hint table name: %s", dynamo_hint_table_name)
        LOGGER.debug("Encryption key name: %s", encryption_key_name)
        aws_dependencies = get_aws_dependencies(
            dynamo_task_table_name=dynamo_task_table_name,
            dynamo_configuration_table_name=dynamo_configuration_table_name,
            dynamo_hint_table_name=dynamo_hint_table_name,
            encryption_key_name=encryption_key_name,
            dynamo_cli_files_table_name=dynamo_cli_files_table_name,
        )
        configuration_service = aws_dependencies.configuration_service
        ai_dependencies = get_ai_dependencies(
            configuration_service=configuration_service
        )
        file_fetcher_dependencies = get_file_fetchers_dependencies(
            configuration_service=configuration_service,
            storage_service=aws_dependencies.storage_service,
            cli_files_repository=aws_dependencies.cli_files_repository,
            cli_files_bucket_name=dynamo_cli_files_bucket_name,
            repo_files_path=repo_files_path,
        )
        outputs_dependencies = get_outputs_dependencies(
            configuration_service=configuration_service,
            storage_service=aws_dependencies.storage_service,
            template_path=template_path,
        )
        run_scan_use_case = RunScanUseCase(
            ai_service=ai_dependencies.ai_service,
            configuration_service=configuration_service,
            file_fetcher_service_factory=file_fetcher_dependencies.file_fetcher_service_factory,
            get_task_use_case=GetTaskUseCase(
                task_repository=aws_dependencies.task_repository
            ),
            mark_task_in_progress_use_case=MarkTaskInProgressUseCase(
                task_repository=aws_dependencies.task_repository
            ),
            mark_task_completed_use_case=MarkTaskCompletedUseCase(
                task_repository=aws_dependencies.task_repository
            ),
            mark_task_failed_use_case=MarkTaskFailedUseCase(
                task_repository=aws_dependencies.task_repository
            ),
            mark_task_error_use_case=MarkTaskErrorUseCase(
                task_repository=aws_dependencies.task_repository
            ),
            hint_use_case=GetHintUseCase(
                hint_repository=aws_dependencies.hint_repository
            ),
            output_service_factory=outputs_dependencies.outputs_service_factory,
            repo_files_path=repo_files_path,
        )
        run_scan_use_case.execute(scan=Scan(id=task_id))
    else:
        LOGGER.error("Invalid infrastructure: %s", infrastructure)
        raise ValueError("Invalid infrastructure")

if __name__ == "__main__":
    env_task_id = os.getenv("TITVO_SCAN_TASK_ID")
    env_infrastructure = os.getenv("TITVO_SCAN_INFRASTRUCTURE", "AWS")
    scan_from_container(env_task_id, env_infrastructure)
