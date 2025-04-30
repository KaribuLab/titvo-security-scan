import os
import json
import logging
import tempfile
import shutil
from unittest.mock import patch, Mock
import pytest
from titvo.infraestructure.file_fetchers.bitbucket_file_fetcher_service import (
    BitbucketFileFetcherService,
    BitbucketFileFetcherServiceArgs,
)

# Disable logging
logging.getLogger("urllib3").setLevel(logging.WARNING)

LOGGER = logging.getLogger(__name__)

# pylint: disable=redefined-outer-name

# Constantes para los módulos que haremos patch
REQUESTS_POST = (
    "titvo.infraestructure.file_fetchers.bitbucket_file_fetcher_service.requests.post"
)
REQUESTS_GET = (
    "titvo.infraestructure.file_fetchers.bitbucket_file_fetcher_service.requests.get"
)


@pytest.fixture
def mock_config_service():
    """Fixture que crea un servicio de configuración de prueba."""
    mock_service = Mock()
    # Configurar el comportamiento para devolver las credenciales
    credentials = {
        "key": "test-client-id",
        "secret": "test-client-secret",
    }
    mock_service.get_secret.return_value = json.dumps(credentials)
    return mock_service


@pytest.fixture
def temp_repo_directory():
    """Fixture que crea un directorio temporal para almacenar archivos."""
    temp_dir = tempfile.mkdtemp()
    yield temp_dir
    # Limpieza: eliminar directorio temporal después de las pruebas
    if os.path.exists(temp_dir):
        shutil.rmtree(temp_dir)


@pytest.fixture
def bitbucket_args():
    """Fixture que crea argumentos de prueba para BitbucketFileFetcherService."""
    return BitbucketFileFetcherServiceArgs(
        bitbucket_repo_slug="test-repo",
        bitbucket_workspace="test-workspace",
        bitbucket_project_key="TEST",
        bitbucket_commit="test-commit-hash",
    )


def test_fetch_files(mock_config_service, temp_repo_directory, bitbucket_args):
    """Test para verificar que fetch_files obtiene y almacena archivos correctamente."""
    # Mock de respuesta para obtener el token de acceso
    token_response = Mock()
    token_response.json.return_value = {"access_token": "test-token"}
    token_response.raise_for_status = Mock()

    # Mock de respuesta para obtener la información del commit
    commit_response = Mock()
    commit_response.json.return_value = {"hash": "full-commit-hash"}
    commit_response.raise_for_status = Mock()

    # Mock de respuesta para obtener el diff
    diff_response = Mock()
    diff_response.text = (
        "diff --git a/src/file1.py b/src/file1.py\n"
        "diff --git a/src/dir/file2.py b/src/dir/file2.py\n"
    )
    diff_response.raise_for_status = Mock()

    # Mock de respuestas para obtener el contenido de los archivos
    file1_response = Mock()
    file1_response.text = 'print("Hello World")\n'
    file1_response.raise_for_status = Mock()

    file2_response = Mock()
    file2_response.text = "def test():\n    return True\n"
    file2_response.raise_for_status = Mock()

    # Crear mock para requests.post
    mock_post = Mock()
    mock_post.return_value = token_response

    # Crear mock para requests.get con side_effect para diferentes URLs
    mock_get = Mock()
    mock_get.side_effect = [
        commit_response,
        diff_response,
        file1_response,
        file2_response,
    ]

    # Aplicar los patches
    with patch(REQUESTS_POST, mock_post):
        with patch(REQUESTS_GET, mock_get):
            # Crear servicio y ejecutar fetch_files
            service = BitbucketFileFetcherService(
                args=bitbucket_args,
                configuration_service=mock_config_service,
                repo_files_path=temp_repo_directory,
            )

            result = service.fetch_files()

            # Verificar que se obtuvieron los archivos correctos
            assert set(result) == {"src/file1.py", "src/dir/file2.py"}

            # Verificar que los archivos fueron escritos correctamente
            file1_path = os.path.join(temp_repo_directory, "src/file1.py")
            with open(file1_path, "r", encoding="utf-8") as f:
                assert f.read() == 'print("Hello World")\n'

            file2_path = os.path.join(temp_repo_directory, "src/dir/file2.py")
            with open(file2_path, "r", encoding="utf-8") as f:
                assert f.read() == "def test():\n    return True\n"

            # Verificar que se realizaron las llamadas HTTP esperadas
            assert mock_post.call_count == 1
            assert mock_get.call_count == 4  # commit + diff + 2 archivos


def test_fetch_files_with_error(
    mock_config_service, temp_repo_directory, bitbucket_args
):
    """Test para verificar el manejo de errores durante la obtención de archivos."""
    # Mock de respuesta para obtener el token de acceso
    token_response = Mock()
    token_response.json.return_value = {"access_token": "test-token"}
    token_response.raise_for_status = Mock()

    # Mock de respuesta para obtener la información del commit
    commit_response = Mock()
    commit_response.json.return_value = {"hash": "full-commit-hash"}
    commit_response.raise_for_status = Mock()

    # Mock de respuesta con error para el diff
    error_response = Mock()
    error_response.raise_for_status.side_effect = Exception("HTTP Error")

    # Crear mock para requests.post
    mock_post = Mock()
    mock_post.return_value = token_response

    # Crear mock para requests.get
    mock_get = Mock()
    mock_get.side_effect = [commit_response, error_response]

    # Aplicar los patches
    with patch(REQUESTS_POST, mock_post):
        with patch(REQUESTS_GET, mock_get):
            # Crear servicio
            service = BitbucketFileFetcherService(
                args=bitbucket_args,
                configuration_service=mock_config_service,
                repo_files_path=temp_repo_directory,
            )

            # Verificar que se propaga la excepción
            with pytest.raises(Exception) as excinfo:
                service.fetch_files()

            assert "HTTP Error" in str(excinfo.value)


def test_fetch_files_with_empty_diff(
    mock_config_service, temp_repo_directory, bitbucket_args
):
    """Test para verificar el comportamiento cuando no hay archivos en el diff."""
    # Mock de respuesta para obtener el token de acceso
    token_response = Mock()
    token_response.json.return_value = {"access_token": "test-token"}
    token_response.raise_for_status = Mock()

    # Mock de respuesta para obtener la información del commit
    commit_response = Mock()
    commit_response.json.return_value = {"hash": "full-commit-hash"}
    commit_response.raise_for_status = Mock()

    # Mock de respuesta para un diff vacío
    empty_diff_response = Mock()
    empty_diff_response.text = ""
    empty_diff_response.raise_for_status = Mock()

    # Crear mock para requests.post
    mock_post = Mock()
    mock_post.return_value = token_response

    # Crear mock para requests.get
    mock_get = Mock()
    mock_get.side_effect = [commit_response, empty_diff_response]

    # Aplicar los patches
    with patch(REQUESTS_POST, mock_post):
        with patch(REQUESTS_GET, mock_get):
            # Crear servicio
            service = BitbucketFileFetcherService(
                args=bitbucket_args,
                configuration_service=mock_config_service,
                repo_files_path=temp_repo_directory,
            )

            # Ejecutar fetch_files
            result = service.fetch_files()

            # Verificar que no se obtuvieron archivos
            assert not result
