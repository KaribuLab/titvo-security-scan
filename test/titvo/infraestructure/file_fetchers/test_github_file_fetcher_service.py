import os
import logging
import tempfile
import shutil
from unittest.mock import patch, Mock
import pytest
from titvo.infraestructure.file_fetchers.github_file_fetcher_service import (
    GithubFileFetcherService,
    GithubFileFetcherServiceArgs,
)

# Disable logging
logging.getLogger("urllib3").setLevel(logging.WARNING)

LOGGER = logging.getLogger(__name__)

# pylint: disable=redefined-outer-name


@pytest.fixture
def mock_config_service():
    """Fixture que crea un servicio de configuración de prueba."""
    mock_service = Mock()
    mock_service.get_value.return_value = "test-value"
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
def github_args():
    """Fixture que crea argumentos de prueba para GithubFileFetcherService."""
    return GithubFileFetcherServiceArgs(
        github_token="test-token",
        github_repo_name="test-owner/test-repo",
        github_commit_sha="test-commit-sha",
        github_assignee="test-assignee",
    )


def test_fetch_files(mock_config_service, temp_repo_directory, github_args):
    """Test para verificar que fetch_files obtiene y almacena archivos correctamente."""
    # Configurar mocks para los objetos de GitHub
    mock_file1 = Mock()
    mock_file1.filename = "file1.py"

    mock_file2 = Mock()
    mock_file2.filename = "dir/file2.py"

    mock_files = [mock_file1, mock_file2]

    # Contenido de archivos codificado en base64
    mock_content1 = Mock()
    # print("Hello World")
    mock_content1.content = "cHJpbnQoIkhlbGxvIFdvcmxkIikK"
    mock_content1.decoded_content = b'print("Hello World")\n'

    mock_content2 = Mock()
    # def test():\n    return True\n
    mock_content2.content = "ZGVmIHRlc3QoKToKICAgIHJldHVybiBUcnVlCg=="
    mock_content2.decoded_content = b"def test():\n    return True\n"

    # Configurar mock del objeto commit
    mock_commit = Mock()
    mock_commit.files = mock_files

    # Configurar mock del objeto repo
    mock_repo = Mock()
    mock_repo.get_commit.return_value = mock_commit
    mock_repo.get_contents.side_effect = lambda filename, ref: (
        mock_content1 if filename == "file1.py" else mock_content2
    )

    # Configurar mock de Github
    mock_github = Mock()
    mock_github.get_repo.return_value = mock_repo

    # Patch la clase Github para retornar nuestro mock
    with patch(
        "titvo.infraestructure.file_fetchers.github_file_fetcher_service.Github",
        return_value=mock_github,
    ):
        # Crear servicio y ejecutar fetch_files
        service = GithubFileFetcherService(
            args=github_args,
            configuration_service=mock_config_service,
            repo_files_path=temp_repo_directory,
        )

        result = service.fetch_files()

        # Verificar que se obtuvieron los archivos correctos
        assert set(result) == {"file1.py", "dir/file2.py"}

        # Verificar que los archivos fueron escritos correctamente
        with open(
            os.path.join(temp_repo_directory, "file1.py"), "r", encoding="utf-8"
        ) as f:
            assert f.read() == 'print("Hello World")\n'

        with open(
            os.path.join(temp_repo_directory, "dir/file2.py"), "r", encoding="utf-8"
        ) as f:
            assert f.read() == "def test():\n    return True\n"

        # Verificar que se llamaron los métodos correctos
        mock_github.get_repo.assert_called_once_with(github_args.github_repo_name)
        mock_repo.get_commit.assert_called_once_with(github_args.github_commit_sha)
        assert mock_repo.get_contents.call_count == 2


def test_fetch_files_with_binary_content(
    mock_config_service, temp_repo_directory, github_args
):
    """Test para verificar que fetch_files maneja contenido binario correctamente."""
    # Configurar mock para un solo archivo
    mock_file = Mock()
    mock_file.filename = "binary_file.bin"

    # Mocking binary content
    mock_content = Mock()
    mock_content.content = None  # Simulando que content no es string
    mock_content.decoded_content = b"Binary content"

    # Configurar mocks
    mock_commit = Mock()
    mock_commit.files = [mock_file]

    mock_repo = Mock()
    mock_repo.get_commit.return_value = mock_commit
    mock_repo.get_contents.return_value = mock_content

    mock_github = Mock()
    mock_github.get_repo.return_value = mock_repo

    # Patch la clase Github
    with patch(
        "titvo.infraestructure.file_fetchers.github_file_fetcher_service.Github",
        return_value=mock_github,
    ):
        service = GithubFileFetcherService(
            args=github_args,
            configuration_service=mock_config_service,
            repo_files_path=temp_repo_directory,
        )

        result = service.fetch_files()

        # Verificar resultado
        assert result == ["binary_file.bin"]

        # Verificar que el archivo fue escrito correctamente
        with open(
            os.path.join(temp_repo_directory, "binary_file.bin"), "r", encoding="utf-8"
        ) as f:
            assert f.read() == "Binary content"


def test_fetch_files_empty_commit(
    mock_config_service, temp_repo_directory, github_args
):
    """Test para verificar el comportamiento cuando un commit no tiene archivos."""
    # Configurar mock con una lista vacía de archivos
    mock_commit = Mock()
    mock_commit.files = []

    mock_repo = Mock()
    mock_repo.get_commit.return_value = mock_commit

    mock_github = Mock()
    mock_github.get_repo.return_value = mock_repo

    # Patch la clase Github
    with patch(
        "titvo.infraestructure.file_fetchers.github_file_fetcher_service.Github",
        return_value=mock_github,
    ):
        service = GithubFileFetcherService(
            args=github_args,
            configuration_service=mock_config_service,
            repo_files_path=temp_repo_directory,
        )

        result = service.fetch_files()

        # Verificar que se devuelve una lista vacía
        assert result == []

        # Verificar que no se llamó a get_contents
        mock_repo.get_contents.assert_not_called()
