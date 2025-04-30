from typing import List
import boto3
from dynamodb_json import json_util as json
from titvo.core.ports.cli_files_repository import CliFilesRepository
from titvo.app.cli_files.cli_files_entities import CliFiles


class DynamoCliFilesRepository(CliFilesRepository):
    def __init__(self, table_name: str):
        self.table_name = table_name
        self.dynamodb_client = boto3.client("dynamodb")

    def get_files(self, batch_id: str) -> List[CliFiles]:
        response = self.dynamodb_client.query(
            TableName=self.table_name,
            IndexName="batch_id_gsi",
            KeyConditionExpression="batch_id = :batch_id",
            ExpressionAttributeValues={":batch_id": {"S": batch_id}},
        )
        cli_files = []
        for item in response["Items"]:
            json_item = json.loads(item)
            cli_files.append(
                CliFiles(
                    batch_id=json_item["batch_id"],
                    file_key=json_item["file_key"],
                    ttl=json_item["ttl"],
                )
            )
        return cli_files
