import logging
import boto3
import pytest
from moto import mock_aws
from titvo.app.cli_files.cli_files_entities import CliFiles
from titvo.infraestructure.aws.dynamo_cli_files_repository import (
    DynamoCliFilesRepository,
)

# Disable logging
logging.getLogger("boto3").setLevel(logging.WARNING)
logging.getLogger("botocore").setLevel(logging.WARNING)
logging.getLogger("moto").setLevel(logging.WARNING)

LOGGER = logging.getLogger(__name__)

# pylint: disable=redefined-outer-name


@pytest.fixture
def dynamodb_table():
    """Fixture que crea una tabla DynamoDB para pruebas."""
    table_name = "test-cli-files-table"
    with mock_aws():
        dynamodb = boto3.resource("dynamodb")
        table = dynamodb.create_table(
            TableName=table_name,
            KeySchema=[{"AttributeName": "file_key", "KeyType": "HASH"}],
            AttributeDefinitions=[
                {"AttributeName": "file_key", "AttributeType": "S"},
                {"AttributeName": "batch_id", "AttributeType": "S"},
            ],
            GlobalSecondaryIndexes=[
                {
                    "IndexName": "batch_id_gsi",
                    "KeySchema": [
                        {"AttributeName": "batch_id", "KeyType": "HASH"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                    "ProvisionedThroughput": {
                        "ReadCapacityUnits": 5,
                        "WriteCapacityUnits": 5,
                    },
                }
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        yield table_name, table


@pytest.fixture
def sample_cli_files():
    """Fixture que crea una lista de archivos CLI de muestra para pruebas."""
    batch_id = "batch-123"
    return [
        CliFiles(
            batch_id=batch_id,
            file_key="file1.py",
            ttl=1631054400,
        ),
        CliFiles(
            batch_id=batch_id,
            file_key="file2.py",
            ttl=1631054400,
        ),
        CliFiles(
            batch_id=batch_id,
            file_key="file3.py",
            ttl=1631054400,
        ),
    ]


@mock_aws
def test_get_files(dynamodb_table, sample_cli_files):
    """Test que verifica la obtención de archivos CLI por batch_id."""
    # Preparar datos
    table_name, table = dynamodb_table
    batch_id = sample_cli_files[0].batch_id

    # Agregar archivos a la tabla
    for cli_file in sample_cli_files:
        file_dict = {
            "batch_id": cli_file.batch_id,
            "file_key": cli_file.file_key,
            "ttl": cli_file.ttl,
        }
        table.put_item(Item=file_dict)

    # Instanciar repositorio
    repository = DynamoCliFilesRepository(table_name)

    # Obtener archivos
    retrieved_files = repository.get_files(batch_id)

    # Verificar
    assert len(retrieved_files) == len(sample_cli_files)

    # Ordenar ambas listas para comparar
    retrieved_files.sort(key=lambda x: x.file_key)
    expected_files = sorted(sample_cli_files, key=lambda x: x.file_key)

    for i, file in enumerate(retrieved_files):
        assert file.batch_id == expected_files[i].batch_id
        assert file.file_key == expected_files[i].file_key
        assert file.ttl == expected_files[i].ttl


@mock_aws
def test_get_files_empty_result(dynamodb_table):
    """Test que verifica el comportamiento cuando no hay archivos para un batch_id."""
    # Preparar datos
    table_name, _ = dynamodb_table
    batch_id = "nonexistent-batch"

    # Instanciar repositorio
    repository = DynamoCliFilesRepository(table_name)

    # Obtener archivos
    retrieved_files = repository.get_files(batch_id)

    # Verificar que se devuelve una lista vacía
    assert len(retrieved_files) == 0
    assert isinstance(retrieved_files, list)
