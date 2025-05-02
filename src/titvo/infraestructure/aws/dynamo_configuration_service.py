from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import boto3
from dynamodb_json import json_util as json
from titvo.core.ports.configuration_service import ConfigurationService


class DynamoConfigurationService(ConfigurationService):
    def __init__(self, table_name: str, encryption_key_name: str):
        self.dynamo_client = boto3.client("dynamodb")
        secret_manager_client = boto3.client("secretsmanager")
        self.encryption_key = secret_manager_client.get_secret_value(
            SecretId=encryption_key_name
        ).get("SecretString")
        self.table_name = table_name

    def get_encryption_key(self) -> str:
        return self.encryption_key

    def get_value(self, name: str) -> str:
        response = self.dynamo_client.get_item(
            TableName=self.table_name, Key={"parameter_id": {"S": name}}
        )
        if "Item" not in response:
            raise KeyError(f"Parameter not found: {name}")
        item = json.loads(response["Item"])
        return item["value"]

    def __decrypt(self, data):
        key = b64decode(self.encryption_key)
        cipher = AES.new(key, AES.MODE_ECB)
        decrypted_data = unpad(cipher.decrypt(b64decode(data)), AES.block_size)
        return decrypted_data.decode("utf-8")

    def get_secret(self, name: str) -> str:
        return self.__decrypt(self.get_value(name))
