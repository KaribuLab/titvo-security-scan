import logging
import boto3
import pytest
from moto import mock_aws
from titvo.app.hint.hint_entities import Hint
from titvo.infraestructure.aws.dynamo_hint_repository import DynamoHintRepository

# Disable logging
logging.getLogger("boto3").setLevel(logging.WARNING)
logging.getLogger("botocore").setLevel(logging.WARNING)
logging.getLogger("moto").setLevel(logging.WARNING)

LOGGER = logging.getLogger(__name__)

# pylint: disable=redefined-outer-name


@pytest.fixture
def dynamodb_table():
    """Fixture que crea una tabla DynamoDB para pruebas."""
    table_name = "test-hints-table"
    with mock_aws():
        dynamodb = boto3.resource("dynamodb")
        table = dynamodb.create_table(
            TableName=table_name,
            KeySchema=[{"AttributeName": "repository_id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "repository_id", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        yield table_name, table


@pytest.fixture
def sample_hint():
    """Fixture que crea un hint de muestra para pruebas."""
    return Hint(
        id="hint-123",
        name="Test Hint",
        slug="test-hint",
        url="https://example.com/hints/test-hint",
        content="Este es un hint de prueba para análisis de seguridad",
    )


@mock_aws
def test_get_hint(dynamodb_table, sample_hint):
    """Test que verifica la obtención de un hint."""
    # Preparar datos
    table_name, table = dynamodb_table

    # Convertir el hint a formato DynamoDB y almacenarlo
    hint_dict = {
        "repository_id": sample_hint.id,
        "hint_id": sample_hint.id,
        "name": sample_hint.name,
        "slug": sample_hint.slug,
        "url": sample_hint.url,
        "hint": sample_hint.content,
    }

    table.put_item(Item=hint_dict)

    # Instanciar repositorio
    repository = DynamoHintRepository(table_name)

    # Obtener hint
    retrieved_hint = repository.get_hint(sample_hint.id)

    # Verificar
    assert retrieved_hint.id == sample_hint.id
    assert retrieved_hint.name == sample_hint.name
    assert retrieved_hint.slug == sample_hint.slug
    assert retrieved_hint.url == sample_hint.url
    assert retrieved_hint.content == sample_hint.content


@mock_aws
def test_hint_not_found(dynamodb_table):
    """Test que verifica el comportamiento cuando un hint no existe."""
    # Preparar datos
    table_name, _ = dynamodb_table

    # Instanciar repositorio
    repository = DynamoHintRepository(table_name)

    # Verificar que se devuelve None cuando el hint no existe
    assert repository.get_hint("nonexistent-hint") is None
