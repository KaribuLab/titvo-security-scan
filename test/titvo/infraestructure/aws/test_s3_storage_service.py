import logging
import os
import tempfile
import boto3
import pytest
from moto import mock_aws
from titvo.core.ports.storage_service import DownloadFileRequest, UploadFileRequest
from titvo.infraestructure.aws.s3_storage_service import S3StorageService

# Disable logging
logging.getLogger("boto3").setLevel(logging.WARNING)
logging.getLogger("botocore").setLevel(logging.WARNING)
logging.getLogger("moto").setLevel(logging.WARNING)

LOGGER = logging.getLogger(__name__)

# pylint: disable=redefined-outer-name


@pytest.fixture
def s3_bucket():
    """Fixture que crea un bucket S3 para pruebas."""
    bucket_name = "test-storage-bucket"
    with mock_aws():
        s3_client = boto3.client("s3")
        s3_client.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={"LocationConstraint": "us-west-2"},
        )
        yield bucket_name, s3_client


@mock_aws
def test_upload_file(s3_bucket):
    """Test que verifica la carga de un archivo a S3."""
    # Preparar datos
    bucket_name, s3_client = s3_bucket
    os.makedirs("test-folder", exist_ok=True)
    file_path = "test-folder/test-file.txt"
    file_content = "Este es el contenido del archivo de prueba"
    with open(file_path, "w", encoding="utf-8") as file:
        file.write(file_content)
    # Crear solicitud de carga
    upload_request = UploadFileRequest(
        container_name=bucket_name,
        input_path=file_path,
        file_path=file_path,
    )
    
    # Instanciar servicio
    storage_service = S3StorageService()
    
    # Cargar archivo
    storage_service.upload_file(upload_request)
    
    # Verificar que el archivo se cargó correctamente
    response = s3_client.get_object(Bucket=bucket_name, Key=file_path)
    retrieved_content = response["Body"].read().decode("utf-8")
    assert retrieved_content == file_content
    os.remove(file_path)
    os.rmdir("test-folder")


@mock_aws
def test_download_file(s3_bucket):
    """Test que verifica la descarga de un archivo de S3."""
    # Preparar datos
    bucket_name, s3_client = s3_bucket
    file_path = "test-folder/test-file.txt"
    file_content = "Este es el contenido del archivo de prueba"
    
    # Cargar un archivo de prueba en S3
    s3_client.put_object(
        Bucket=bucket_name,
        Key=file_path,
        Body=file_content.encode("utf-8")
    )
    
    # Crear un archivo temporal para la descarga
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        output_path = temp_file.name
    
    try:
        # Crear solicitud de descarga
        download_request = DownloadFileRequest(
            container_name=bucket_name,
            file_path=file_path,
            output_path=output_path
        )
        
        # Instanciar servicio
        storage_service = S3StorageService()
        
        # Descargar archivo
        storage_service.download_file(download_request)
        
        # Verificar que el archivo se descargó correctamente
        with open(output_path, "r", encoding="utf-8") as file:
            downloaded_content = file.read()
        
        assert downloaded_content == file_content
    finally:
        # Limpiar archivo temporal
        if os.path.exists(output_path):
            os.remove(output_path)


@mock_aws
def test_download_nonexistent_file(s3_bucket):
    """Test que verifica el comportamiento al descargar un archivo inexistente."""
    # Preparar datos
    bucket_name, _ = s3_bucket
    
    # Crear un archivo temporal para la descarga
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        output_path = temp_file.name
    
    try:
        # Crear solicitud de descarga para un archivo que no existe
        download_request = DownloadFileRequest(
            container_name=bucket_name,
            file_path="nonexistent-file.txt",
            output_path=output_path
        )
        
        # Instanciar servicio
        storage_service = S3StorageService()
        
        # Verificar que se lance una excepción al intentar descargar un archivo inexistente
        with pytest.raises(Exception):
            storage_service.download_file(download_request)
    finally:
        # Limpiar archivo temporal
        if os.path.exists(output_path):
            os.remove(output_path)


@mock_aws
def test_upload_file_with_content_type(s3_bucket):
    """Test que verifica la carga de un archivo a S3 con content_type específico."""
    # Preparar datos
    bucket_name, s3_client = s3_bucket
    os.makedirs("test-folder", exist_ok=True)
    file_path = "test-folder/test-file.html"
    file_content = "<html><body>Test content</body></html>"
    with open(file_path, "w", encoding="utf-8") as file:
        file.write(file_content)
    
    # Crear solicitud de carga con content_type
    upload_request = UploadFileRequest(
        container_name=bucket_name,
        input_path=file_path,
        file_path=file_path,
        content_type="text/html; charset=utf-8",
    )
    
    # Instanciar servicio
    storage_service = S3StorageService()
    
    # Cargar archivo
    storage_service.upload_file(upload_request)
    
    # Verificar que el archivo se cargó correctamente
    response = s3_client.get_object(Bucket=bucket_name, Key=file_path)
    retrieved_content = response["Body"].read().decode("utf-8")
    
    # Verificar el content-type
    assert response["ContentType"] == "text/html; charset=utf-8"
    assert retrieved_content == file_content
    
    os.remove(file_path)
    os.rmdir("test-folder")
