import logging
import json
from datetime import datetime
import boto3
import pytest
from moto import mock_aws
from dynamodb_json import json_util as dynamo_json
from titvo.app.task.task_entities import Task, TaskStatus, TaskSource
from titvo.infraestructure.aws.dynamo_task_repository import DynamoTaskRepository

# Disable logging
logging.getLogger("boto3").setLevel(logging.WARNING)
logging.getLogger("botocore").setLevel(logging.WARNING)
logging.getLogger("moto").setLevel(logging.WARNING)

LOGGER = logging.getLogger(__name__)

# pylint: disable=redefined-outer-name


@pytest.fixture
def dynamodb_table():
    """Fixture que crea una tabla DynamoDB para pruebas."""
    table_name = "test-tasks-table"
    with mock_aws():
        dynamodb = boto3.resource("dynamodb")
        table = dynamodb.create_table(
            TableName=table_name,
            KeySchema=[{"AttributeName": "scan_id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "scan_id", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        yield table_name, table


@pytest.fixture
def sample_task():
    """Fixture que crea una tarea de muestra para pruebas."""
    return Task(
        id="task-123",
        result={"vulnerabilities": []},
        args={"repository": "repo1"},
        hint_id="hint-123",
        scaned_files=0,
        created_at=datetime(2024, 1, 1, 12, 0, 0),
        updated_at=datetime(2024, 1, 1, 12, 0, 0),
        status=TaskStatus.PENDING,
        source=TaskSource.GITHUB,
    )


@mock_aws
def test_get_task(dynamodb_table, sample_task):
    """Test que verifica la obtención de una tarea."""
    # Preparar datos
    table_name, table = dynamodb_table

    # Convertir la tarea a formato DynamoDB y almacenarla
    task_dict = {
        "scan_id": sample_task.id,
        "scan_result": sample_task.result,
        "args": sample_task.args,
        "repository_id": sample_task.hint_id,
        "scaned_files": sample_task.scaned_files,
        "created_at": sample_task.created_at.isoformat(),
        "updated_at": sample_task.updated_at.isoformat(),
        "status": sample_task.status.value,
        "source": sample_task.source.value,
    }

    table.put_item(Item=task_dict)

    # Instanciar repositorio
    repository = DynamoTaskRepository(table_name)

    # Obtener tarea
    retrieved_task = repository.get_task(sample_task.id)

    # Verificar
    assert retrieved_task.id == sample_task.id
    assert retrieved_task.result == sample_task.result
    assert retrieved_task.args == sample_task.args
    assert retrieved_task.hint_id == sample_task.hint_id
    assert retrieved_task.scaned_files == sample_task.scaned_files
    assert retrieved_task.status == sample_task.status
    assert retrieved_task.source == sample_task.source


@mock_aws
def test_update_task(dynamodb_table, sample_task):
    """Test que verifica la actualización de una tarea."""
    # Preparar datos
    table_name, table = dynamodb_table

    # Convertir la tarea a formato DynamoDB y almacenarla
    task_dict = {
        "scan_id": sample_task.id,
        "scan_result": sample_task.result,
        "args": sample_task.args,
        "repository_id": sample_task.hint_id,
        "scaned_files": sample_task.scaned_files,
        "created_at": sample_task.created_at.isoformat(),
        "updated_at": sample_task.updated_at.isoformat(),
        "status": sample_task.status.value,
        "source": sample_task.source.value,
    }

    # Convertir a formato DynamoDB y almacenar
    table.put_item(Item=task_dict)

    # Instanciar repositorio
    repository = DynamoTaskRepository(table_name)

    # Modificar la tarea
    updated_task = Task(
        id=sample_task.id,
        result={"vulnerabilities": ["found-vulnerability"]},
        args=sample_task.args,
        hint_id=sample_task.hint_id,
        scaned_files=5,
        created_at=sample_task.created_at,
        updated_at=datetime(2024, 1, 1, 13, 0, 0),
        status=TaskStatus.COMPLETED,
        source=sample_task.source,
    )

    # Actualizar tarea en DynamoDB
    result = repository.update_task(updated_task)

    # Verificar que el resultado devuelto es correcto
    assert result.id == updated_task.id
    assert result.result == updated_task.result
    assert result.scaned_files == updated_task.scaned_files
    assert result.status == updated_task.status

    # Obtener tarea actualizada directamente de DynamoDB para verificar persistencia
    response = table.get_item(Key={"scan_id": updated_task.id})
    item = response["Item"]

    # Verificar que se haya actualizado en la base de datos
    assert item["scan_id"] == updated_task.id
    assert dynamo_json.loads(item["scan_result"]) == updated_task.result
    assert item["scaned_files"] == updated_task.scaned_files
    assert item["status"] == updated_task.status.value


@mock_aws
def test_task_not_found(dynamodb_table):
    """Test que verifica el comportamiento cuando una tarea no existe."""
    # Preparar datos
    table_name, _ = dynamodb_table

    # Instanciar repositorio
    repository = DynamoTaskRepository(table_name)

    # Verificar que se lance una excepción cuando la tarea no existe
    with pytest.raises(KeyError):
        repository.get_task("nonexistent-task")
