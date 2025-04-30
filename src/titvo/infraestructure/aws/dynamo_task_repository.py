import logging
import json
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
        return Task(
            id=item["scan_id"],
            result=item["scan_result"],
            args=item["args"],
            hint_id=item["repository_id"],
            scaned_files=item["scaned_files"],
            created_at=item["created_at"],
            updated_at=item["updated_at"],
            status=TaskStatus(item["status"]),
            source=TaskSource(item["source"]),
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
        expression_attribute_values = {
            ":scan_result": {"M": json.loads(dynamo_json.dumps(task.result))},
            ":args": {"M": json.loads(dynamo_json.dumps(task.args))},
            ":hint_id": {"S": task.hint_id},
            ":scaned_files": {"N": str(task.scaned_files)},
            ":created_at": {"S": task.created_at.isoformat()},
            ":updated_at": {"S": task.updated_at.isoformat()},
            ":status": {"S": task.status.value},
            ":source": {"S": task.source.value},
        }
        LOGGER.debug("Update expression: %s", update_expression)
        LOGGER.debug("Expression attribute names: %s", expression_attribute_names)
        LOGGER.debug("Expression attribute values: %s", expression_attribute_values)
        response = self.dynamo_client.update_item(
            TableName=self.table_name,
            Key={"scan_id": {"S": task.id}},
            UpdateExpression=update_expression,
            ExpressionAttributeNames=expression_attribute_names,
            ExpressionAttributeValues=expression_attribute_values,
        )
        LOGGER.debug("Task updated: %s", response)
        return task
