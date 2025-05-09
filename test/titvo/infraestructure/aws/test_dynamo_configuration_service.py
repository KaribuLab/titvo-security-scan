import logging
import base64
from unittest.mock import patch
import boto3
import pytest
from moto import mock_aws
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from titvo.infraestructure.aws.dynamo_configuration_service import (
    DynamoConfigurationService,
)

# Disable logging
logging.getLogger("boto3").setLevel(logging.WARNING)
logging.getLogger("botocore").setLevel(logging.WARNING)
logging.getLogger("moto").setLevel(logging.WARNING)

# pylint: disable=redefined-outer-name


@pytest.fixture
def dynamodb_table():
    """Fixture que crea una tabla DynamoDB para pruebas."""
    table_name = "test-configuration-table"
    with mock_aws():
        dynamodb = boto3.resource("dynamodb")
        table = dynamodb.create_table(
            TableName=table_name,
            KeySchema=[{"AttributeName": "parameter_id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "parameter_id", "AttributeType": "S"}],
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
        )
        yield table_name, table

@pytest.fixture
def secretsmanager_key():
    """Fixture que crea una clave en Secrets Manager para pruebas."""
    key_name = "test-encryption-key"
    encryption_key = base64.b64encode(b"mysecretkey12345").decode("utf-8")
    with mock_aws():
        secretsmanager = boto3.client("secretsmanager", region_name="us-east-1")
        secretsmanager.create_secret(Name=key_name, SecretString=encryption_key)
        yield key_name, encryption_key


@mock_aws
def test_get_value(dynamodb_table, secretsmanager_key):
    """Test que verifica la obtención de un valor no encriptado."""
    # Preparar datos
    table_name, table = dynamodb_table
    key_name, _ = secretsmanager_key

    # Agregar un item de prueba
    table.put_item(Item={"parameter_id": "test_config_key", "value": "test_config_value"})

    # Instanciar servicio
    service = DynamoConfigurationService(table_name, key_name)

    # Obtener valor
    value = service.get_value("test_config_key")

    # Verificar
    assert value == "test_config_value"


@mock_aws
def test_get_secret(dynamodb_table, secretsmanager_key):
    """Test que verifica la obtención y desencriptación de un valor secreto."""
    # Preparar datos
    table_name, table = dynamodb_table
    key_name, encryption_key = secretsmanager_key

    # Crear valor secreto encriptado
    key = base64.b64decode(encryption_key)
    cipher = AES.new(key, AES.MODE_ECB)
    secret_data = "topsecret123"
    padded_data = pad(secret_data.encode("utf-8"), AES.block_size)
    encrypted_data = base64.b64encode(cipher.encrypt(padded_data)).decode("utf-8")

    # Agregar un item encriptado de prueba
    table.put_item(Item={"parameter_id": "test_secret_key", "value": encrypted_data})

    # Instanciar servicio
    service = DynamoConfigurationService(table_name, key_name)
    
    # Crear mocks para get_value y decrypt
    with patch.object(service, 'get_value', wraps=service.get_value) as mock_get_value:
        with patch.object(service, 'decrypt', wraps=service.decrypt) as mock_decrypt:
            # Obtener valor secreto desencriptado
            value = service.get_secret("test_secret_key")
            
            # Verificar el valor obtenido
            assert value == "topsecret123"
            
            # Verificar que se llamaron los métodos correctamente
            mock_get_value.assert_called_once_with("test_secret_key")
            mock_decrypt.assert_called_once_with(encrypted_data)


@mock_aws
def test_item_not_found(dynamodb_table, secretsmanager_key):
    """Test que verifica el comportamiento cuando un item no existe."""
    # Preparar datos
    table_name, _ = dynamodb_table
    key_name, _ = secretsmanager_key

    # Instanciar servicio
    service = DynamoConfigurationService(table_name, key_name)

    # Verificar que se lance una excepción cuando el item no existe
    with pytest.raises(KeyError):
        service.get_value("nonexistent_key")


@mock_aws
def test_get_encryption_key(secretsmanager_key):
    """Test que verifica la obtención de la clave de encriptación."""
    # Preparar datos
    key_name, encryption_key = secretsmanager_key

    # Instanciar servicio con una tabla ficticia (no la usaremos)
    with mock_aws():
        service = DynamoConfigurationService("dummy-table", key_name)
        
        # Obtener clave de encriptación
        result = service.get_encryption_key()
        
        # Verificar que la clave es correcta
        assert result == encryption_key


@mock_aws
def test_decrypt_method(secretsmanager_key):
    """Test que verifica el funcionamiento del método decrypt."""
    # Preparar datos
    key_name, encryption_key = secretsmanager_key
    
    # Crear un valor encriptado para pruebas
    key = base64.b64decode(encryption_key)
    cipher = AES.new(key, AES.MODE_ECB)
    test_data = "test-secret-value"
    padded_data = pad(test_data.encode("utf-8"), AES.block_size)
    encrypted_data = base64.b64encode(cipher.encrypt(padded_data)).decode("utf-8")
    
    # Instanciar servicio con una tabla ficticia (no la usaremos)
    with mock_aws():
        service = DynamoConfigurationService("dummy-table", key_name)
        
        # Desencriptar los datos
        decrypted = service.decrypt(encrypted_data)
        
        # Verificar el resultado
        assert decrypted == test_data
