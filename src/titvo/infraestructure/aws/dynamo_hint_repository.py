import boto3
from dynamodb_json import json_util as json
from titvo.core.ports.hint_repository import HintRepository
from titvo.app.hint.hint_entities import Hint


class DynamoHintRepository(HintRepository):
    def __init__(self, table_name: str):
        self.table_name = table_name
        self.dynamo_client = boto3.client("dynamodb")

    def get_hint(self, hint_id: str) -> Hint | None:
        response = self.dynamo_client.get_item(
            TableName=self.table_name,
            Key={"repository_id": {"S": hint_id}},
        )
        if "Item" not in response:
            return None
        item = json.loads(response["Item"])
        return Hint(
            id=item["repository_id"],
            name=item["name"],
            slug=item["slug"],
            url=item["url"],
            content=item["hint"],
        )
