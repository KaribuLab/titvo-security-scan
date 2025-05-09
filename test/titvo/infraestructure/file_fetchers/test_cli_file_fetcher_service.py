import os
import io
import tarfile
import logging
import tempfile
import shutil
from unittest.mock import Mock
import boto3
import pytest
from moto import mock_aws
from titvo.app.cli_files.cli_files_entities import CliFiles
from titvo.infraestructure.aws.s3_storage_service import S3StorageService
from titvo.core.ports.storage_service import DownloadFileRequest
from titvo.infraestructure.file_fetchers.cli_file_fetcher_service import (
    CliFileFetcherService,
    CliFileFetcherServiceArgs,
)

# Disable logging
logging.getLogger("boto3").setLevel(logging.WARNING)
logging.getLogger("botocore").setLevel(logging.WARNING)
logging.getLogger("moto").setLevel(logging.WARNING)

LOGGER = logging.getLogger(__name__)

# pylint: disable=redefined-outer-name


@pytest.fixture
def mock_config_service():
    """Fixture que crea un servicio de configuración de prueba."""
    mock_service = Mock()
    return mock_service


@pytest.fixture
def s3_bucket():
    """Fixture que crea un bucket S3 para pruebas."""
    bucket_name = "test-bucket"
    with mock_aws():
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket=bucket_name)

        # Crear archivos tar.gz en memoria y subir a S3
        for file_key in ["files.tar.gz", "more_files.tar.gz"]:
            tar_output = io.BytesIO()
            with tarfile.open(fileobj=tar_output, mode="w:gz") as tar:
                # Crear y añadir algunos archivos al tar
                info = tarfile.TarInfo("test_file1.py")
                data = b'print("Hello World")'
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))

                info = tarfile.TarInfo("dir/test_file2.py")
                data = b"def test():\n    return True"
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))

            # Resetear el puntero de BytesIO
            tar_output.seek(0)
            s3.put_object(Bucket=bucket_name, Key=file_key, Body=tar_output.getvalue())

        yield bucket_name


@pytest.fixture
def mock_cli_files_repository():
    """Fixture que crea un repositorio de archivos CLI de prueba."""
    mock_repo = Mock()
    mock_repo.get_files.return_value = [
        CliFiles(batch_id="batch-123", file_key="files.tar.gz", ttl=1631054400),
        CliFiles(batch_id="batch-123", file_key="more_files.tar.gz", ttl=1631054400),
    ]
    return mock_repo


@pytest.fixture
def temp_repo_directory():
    """Fixture que crea un directorio temporal para almacenar archivos."""
    temp_dir = tempfile.mkdtemp()
    yield temp_dir
    # Limpieza: eliminar directorio temporal después de las pruebas
    if os.path.exists(temp_dir):
        shutil.rmtree(temp_dir)


@pytest.fixture
def cli_args():
    """Fixture que crea argumentos de prueba para CliFileFetcherService."""
    return CliFileFetcherServiceArgs(
        batch_id="batch-123",
        repository_slug="test-repo",
    )


@mock_aws
def test_fetch_files(
    mock_config_service,
    s3_bucket,
    mock_cli_files_repository,
    temp_repo_directory,
    cli_args,
):
    """Test que verifica la obtención y extracción de archivos CLI."""
    # Crear servicio de almacenamiento S3 real (pero simulado por moto)
    storage_service = S3StorageService()

    # Crear servicio
    service = CliFileFetcherService(
        args=cli_args,
        configuration_service=mock_config_service,
        storage_service=storage_service,
        cli_files_repository=mock_cli_files_repository,
        cli_files_bucket_name=s3_bucket,
        repo_files_path=temp_repo_directory,
    )

    # Ejecutar fetch_files
    result = service.fetch_files()

    # Verificar que los archivos fueron extraídos correctamente
    assert len(result) == 4  # 2 archivos por cada tar.gz
    assert "test_file1.py" in result
    assert "dir/test_file2.py" in result

    # Verificar que los archivos existen en el sistema de archivos
    assert os.path.exists(os.path.join(temp_repo_directory, "test_file1.py"))
    assert os.path.exists(os.path.join(temp_repo_directory, "dir/test_file2.py"))

    # Verificar que los archivos tar.gz fueron eliminados después de la extracción
    assert not os.path.exists(os.path.join(temp_repo_directory, "files.tar.gz"))
    assert not os.path.exists(os.path.join(temp_repo_directory, "more_files.tar.gz"))

    # Verificar que se llamó al repositorio de archivos CLI
    mock_cli_files_repository.get_files.assert_called_once_with(cli_args.batch_id)


@mock_aws
def test_fetch_files_empty_repository(
    mock_config_service, s3_bucket, temp_repo_directory, cli_args
):
    """Test que verifica el comportamiento cuando no hay archivos en el repositorio."""
    # Crear mock de repositorio vacío
    empty_repo = Mock()
    empty_repo.get_files.return_value = []

    # Crear servicio de almacenamiento S3 real (pero simulado por moto)
    storage_service = S3StorageService()

    # Crear servicio
    service = CliFileFetcherService(
        args=cli_args,
        configuration_service=mock_config_service,
        storage_service=storage_service,
        cli_files_repository=empty_repo,
        cli_files_bucket_name=s3_bucket,
        repo_files_path=temp_repo_directory,
    )

    # Ejecutar fetch_files
    result = service.fetch_files()

    # Verificar que no se obtuvieron archivos
    assert not result

    # Verificar que se llamó al repositorio de archivos CLI
    empty_repo.get_files.assert_called_once_with(cli_args.batch_id)


@mock_aws
def test_fetch_files_storage_error(
    mock_config_service, mock_cli_files_repository, temp_repo_directory, cli_args
):
    """Test que verifica el manejo de errores al descargar archivos inexistentes."""
    # Crear un bucket vacío para forzar error
    s3 = boto3.client("s3", region_name="us-east-1")
    bucket_name = "empty-bucket"
    s3.create_bucket(Bucket=bucket_name)

    # Crear servicio de almacenamiento S3 real (pero simulado por moto)
    storage_service = S3StorageService()

    # Crear servicio
    service = CliFileFetcherService(
        args=cli_args,
        configuration_service=mock_config_service,
        storage_service=storage_service,
        cli_files_repository=mock_cli_files_repository,
        cli_files_bucket_name=bucket_name,
        repo_files_path=temp_repo_directory,
    )

    # Verificar que se propaga alguna excepción al intentar descargar archivos inexistentes
    with pytest.raises(Exception):
        service.fetch_files()

    # Verificar que se llamó al repositorio de archivos CLI
    mock_cli_files_repository.get_files.assert_called_once_with(cli_args.batch_id)


@mock_aws
def test_download_file_call_parameters(
    mock_config_service,
    s3_bucket,
    mock_cli_files_repository,
    temp_repo_directory,
    cli_args,
):
    """Test que verifica que download_file se llama con los parámetros correctos."""
    # Crear archivos tar.gz en memoria
    files_tar_content = io.BytesIO()
    with tarfile.open(fileobj=files_tar_content, mode="w:gz") as tar:
        # Añadir primer archivo
        info = tarfile.TarInfo("file1.py")
        data = b'print("Hello from file1")'
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))

    more_files_tar_content = io.BytesIO()
    with tarfile.open(fileobj=more_files_tar_content, mode="w:gz") as tar:
        # Añadir segundo archivo en un subdirectorio
        info = tarfile.TarInfo("dir/file2.py")
        data = b"def test():\n    return True"
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))

    # Reposicionar los punteros de BytesIO al inicio
    files_tar_content.seek(0)
    more_files_tar_content.seek(0)

    # Crear cliente S3 y subir los archivos al bucket
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.put_object(
        Bucket=s3_bucket, Key="files.tar.gz", Body=files_tar_content.getvalue()
    )
    s3.put_object(
        Bucket=s3_bucket,
        Key="more_files.tar.gz",
        Body=more_files_tar_content.getvalue(),
    )

    # Configurar el mock del repositorio para devolver los archivos
    mock_cli_files_repository.get_files.return_value = [
        CliFiles(batch_id="batch-123", file_key="files.tar.gz", ttl=1631054400),
        CliFiles(batch_id="batch-123", file_key="more_files.tar.gz", ttl=1631054400),
    ]

    # Crear servicio de almacenamiento real (simulado por moto)
    storage_service = S3StorageService()

    # Crear servicio
    service = CliFileFetcherService(
        args=cli_args,
        configuration_service=mock_config_service,
        storage_service=storage_service,
        cli_files_repository=mock_cli_files_repository,
        cli_files_bucket_name=s3_bucket,
        repo_files_path=temp_repo_directory,
    )

    # Ejecutar fetch_files - ahora usará la implementación real con el S3 simulado
    result = service.fetch_files()

    # Verificar el resultado
    assert len(result) == 2
    assert "file1.py" in result
    assert "dir/file2.py" in result

    # Verificar que se llamó al repositorio de archivos CLI
    mock_cli_files_repository.get_files.assert_called_once_with(cli_args.batch_id)

    # Verificar que los archivos se extrajeron correctamente al sistema de archivos
    assert os.path.exists(os.path.join(temp_repo_directory, "file1.py"))
    assert os.path.exists(os.path.join(temp_repo_directory, "dir/file2.py"))


@mock_aws
def test_s3_download_permissions():
    """Test que verifica que se pueden descargar archivos con los permisos adecuados en S3."""
    # Crear un bucket S3 para la prueba
    bucket_name = "test-download-bucket"
    file_key = "test-file.tar.gz"

    # Crear cliente S3 y bucket
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket=bucket_name)

    # Crear un archivo tar.gz de prueba y subirlo a S3
    tar_output = io.BytesIO()
    with tarfile.open(fileobj=tar_output, mode="w:gz") as tar:
        info = tarfile.TarInfo("test_file.py")
        data = b'print("Hello World")'
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))

    tar_output.seek(0)
    s3.put_object(Bucket=bucket_name, Key=file_key, Body=tar_output.getvalue())

    # Crear un directorio temporal para la prueba
    temp_dir = tempfile.mkdtemp()
    output_path = os.path.join(temp_dir, file_key)

    try:
        # Crear el servicio de almacenamiento real (con moto interceptando las llamadas a AWS)
        storage_service = S3StorageService()

        # Ejecutar download_file - con moto esto debe funcionar y no necesita patch
        storage_service.download_file(
            DownloadFileRequest(
                container_name=bucket_name,
                file_path=file_key,
                output_path=output_path,
            )
        )

        # Verificar que el archivo se descargó correctamente
        assert os.path.exists(output_path)

        # Verificar que el contenido del archivo descargado es correcto
        with tarfile.open(output_path, "r:gz") as tar:
            file_info = tar.getmember("test_file.py")
            file_content = tar.extractfile(file_info).read().decode("utf-8")
            assert file_content == 'print("Hello World")'
    finally:
        # Limpieza
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
