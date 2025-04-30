import boto3
from dynamodb_json import json_util as json
from titvo.core.ports.hint_repository import HintRepository
from titvo.app.hint.hint_entities import Hint


class DynamoHintRepository(HintRepository):
    def __init__(self, table_name: str):
        self.table_name = table_name
        self.dynamo_client = boto3.client("dynamodb")

    def get_hint(self, hint_id: str) -> Hint:
        response = self.dynamo_client.get_item(
            TableName=self.table_name,
            Key={"hint_id": {"S": hint_id}},
        )
        item = json.loads(response["Item"])
        return Hint(
            id=item["hint_id"],
            name=item["name"],
            slug=item["slug"],
            url=item["url"],
            content=item["hint"],
        )
