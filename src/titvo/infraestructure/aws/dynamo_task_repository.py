import logging
import json
from datetime import datetime
import boto3
from dynamodb_json import json_util as dynamo_json
from titvo.app.task.task_entities import Task, TaskStatus, TaskSource
from titvo.core.ports.task_repository import TaskRepository

LOGGER = logging.getLogger(__name__)


class DynamoTaskRepository(TaskRepository):
    def __init__(self, table_name: str):
        self.dynamo_client = boto3.client("dynamodb")
        self.table_name = table_name

    def get_task(self, task_id: str) -> Task:
        response = self.dynamo_client.get_item(
            TableName=self.table_name, Key={"scan_id": {"S": task_id}}
        )
        item = dynamo_json.loads(response["Item"])
        created_at = item["created_at"]
        updated_at = item["updated_at"]
        if isinstance(created_at, str):
            created_at = datetime.fromisoformat(created_at)
        if isinstance(updated_at, str):
            updated_at = datetime.fromisoformat(updated_at)
        LOGGER.debug("Item: %s", item)
        return Task(
            id=item.get("scan_id", ""),
            result=item.get("scan_result", {}),
            args=item.get("args", {}),
            hint_id=item.get("repository_id", ""),
            scaned_files=item.get("scaned_files", 0),
            created_at=created_at,
            updated_at=updated_at,
            status=TaskStatus(item.get("status", TaskStatus.PENDING.value)),
            source=TaskSource(item.get("source", TaskSource.GITHUB.value)),
        )

    def update_task(self, task: Task) -> Task:
        LOGGER.debug("Updating task: %s", task)
        update_expression = (
            "set #scan_result = :scan_result, "
            "#args = :args, "
            "#hint_id = :hint_id, "
            "#scaned_files = :scaned_files, "
            "#created_at = :created_at, "
            "#updated_at = :updated_at, "
            "#status = :status, "
            "#source = :source"
        )
        expression_attribute_names = {
            "#scan_result": "scan_result",
            "#args": "args",
            "#hint_id": "hint_id",
            "#scaned_files": "scaned_files",
            "#created_at": "created_at",
            "#updated_at": "updated_at",
            "#status": "status",
            "#source": "source",
        }

        created_at = task.created_at
        updated_at = task.updated_at

        if isinstance(created_at, str):
            created_at = datetime.fromisoformat(created_at)
        if isinstance(updated_at, str):
            updated_at = datetime.fromisoformat(updated_at)

        LOGGER.debug("Created at: %s", created_at)
        LOGGER.debug("Updated at: %s", updated_at)
        LOGGER.debug("Result: %s", task.result)
        LOGGER.debug("Args: %s", task.args)
        LOGGER.debug("Hint id: %s", task.hint_id)
        LOGGER.debug("Scaned files: %s", task.scaned_files)
        LOGGER.debug("Status: %s", task.status)
        LOGGER.debug("Source: %s", task.source)
        scan_result = dynamo_json.dumps(task.result)
        scan_args = dynamo_json.dumps(task.args)
        expression_attribute_values = {
            ":scan_result": {"M": json.loads(scan_result)},
            ":args": {"M": json.loads(scan_args)},
            ":hint_id": {"S": task.hint_id},
            ":scaned_files": {"N": str(task.scaned_files)},
            ":created_at": {"S": created_at.isoformat()},
            ":updated_at": {"S": updated_at.isoformat()},
            ":status": {"S": task.status.value},
            ":source": {"S": task.source.value},
        }
        LOGGER.debug("Update expression: %s", update_expression)
        LOGGER.debug("Expression attribute names: %s", expression_attribute_names)
        LOGGER.debug("Expression attribute values: %s", expression_attribute_values)
        self.dynamo_client.update_item(
            TableName=self.table_name,
            Key={"scan_id": {"S": task.id}},
            UpdateExpression=update_expression,
            ExpressionAttributeNames=expression_attribute_names,
            ExpressionAttributeValues=expression_attribute_values,
        )
        return task
