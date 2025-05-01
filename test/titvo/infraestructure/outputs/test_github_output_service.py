from unittest.mock import patch, Mock
import pytest
from titvo.infraestructure.outputs.github_output_service import (
    GithubOutputService,
    GithubOutputArgs,
    GithubOutputResult,
)
from titvo.app.scan.scan_entities import ScanResult, Annotation, ScanStatus

# Constante para el módulo que vamos a hacer patch
GITHUB_MODULE = "titvo.infraestructure.outputs.github_output_service.Github"

# pylint: disable=redefined-outer-name

@pytest.fixture
def mock_config_service():
    """Fixture que crea un mock del servicio de configuración."""
    return Mock()


@pytest.fixture
def github_args():
    """Fixture que crea argumentos para el GithubOutputService."""
    return GithubOutputArgs(
        github_token="test-token",
        github_repo_name="test-owner/test-repo",
        github_commit_sha="abcdef1234567890",
        github_assignee="test-user",
    )


@pytest.fixture
def sample_scan_result():
    """Fixture que crea un resultado de escaneo de prueba."""
    return ScanResult(
        introduction="Se ha realizado un análisis de seguridad del código",
        status=ScanStatus.FAILED,
        number_of_issues=1,
        annotations=[
            Annotation(
                title="Ejecución de código arbitrario",
                description="La función eval puede ejecutar código arbitrario",
                severity="CRITICAL",
                path="app/main.py",
                line=10,
                summary="Uso de eval con entrada no sanitizada",
                code="eval(input())",
                recommendation="Evitar el uso de eval con entrada del usuario",
            )
        ],
    )


def test_execute_create_issue(
    mock_config_service, github_args, sample_scan_result
):
    """Test que verifica la creación de issues en GitHub."""
    # Crear mocks para la API de GitHub
    mock_issue = Mock()
    mock_issue.html_url = "https://github.com/test-owner/test-repo/issues/1"
    
    mock_repo = Mock()
    mock_repo.create_issue.return_value = mock_issue
    
    mock_commit = Mock()
    mock_commit.commit.author.name = "Test Author"
    mock_repo.get_commit.return_value = mock_commit
    
    mock_github = Mock()
    mock_github.get_repo.return_value = mock_repo
    
    # Aplicar patch al constructor de Github
    with patch(GITHUB_MODULE, return_value=mock_github):
        # Crear servicio y ejecutar
        service = GithubOutputService(
            args=github_args, configuration_service=mock_config_service
        )
        result = service.execute(sample_scan_result)
        
        # Verificar que se obtuvo el repositorio correcto
        mock_github.get_repo.assert_called_once_with(github_args.github_repo_name)
        
        # Verificar que se obtuvo el commit correcto
        mock_repo.get_commit.assert_called_once_with(github_args.github_commit_sha)
        
        # Verificar que se creó el issue con el título y cuerpo esperados
        mock_repo.create_issue.assert_called_once()
        call_args = mock_repo.create_issue.call_args[1]
        assert "[BUG] Problema de seguridad" in call_args["title"]
        assert "Ejecución de código arbitrario" in call_args["body"]
        assert "CRITICAL" in call_args["body"]
        assert "app/main.py" in call_args["body"]
        assert "Evitar el uso de eval" in call_args["body"]
        assert call_args["labels"] == ["bug"]
        
        # Verificar que se asignó el issue al usuario configurado
        mock_issue.add_to_assignees.assert_called_once_with(github_args.github_assignee)
        
        # Verificar el resultado
        assert isinstance(result, GithubOutputResult)
        assert result.issue_url == "https://github.com/test-owner/test-repo/issues/1"
        assert result.to_dict() == {"issue_url": "https://github.com/test-owner/test-repo/issues/1"}


def test_execute_without_assignee(
    mock_config_service, github_args, sample_scan_result
):
    """Test que verifica la creación de issues sin asignar a un usuario."""
    # Modificar args para quitar el asignee
    github_args.github_assignee = ""
    
    # Crear mocks para la API de GitHub
    mock_issue = Mock()
    mock_issue.html_url = "https://github.com/test-owner/test-repo/issues/1"
    
    mock_repo = Mock()
    mock_repo.create_issue.return_value = mock_issue
    
    mock_commit = Mock()
    mock_commit.commit.author.name = "Test Author"
    mock_repo.get_commit.return_value = mock_commit
    
    mock_github = Mock()
    mock_github.get_repo.return_value = mock_repo
    
    # Aplicar patch al constructor de Github
    with patch(GITHUB_MODULE, return_value=mock_github):
        # Crear servicio y ejecutar
        service = GithubOutputService(
            args=github_args, configuration_service=mock_config_service
        )
        result = service.execute(sample_scan_result)
        
        # Verificar que NO se asignó el issue
        mock_issue.add_to_assignees.assert_not_called()
        
        # Verificar el resultado
        assert isinstance(result, GithubOutputResult)
        assert result.issue_url == "https://github.com/test-owner/test-repo/issues/1"


def test_execute_multiple_annotations(
    mock_config_service, github_args
):
    """Test que verifica la creación de issues con múltiples anotaciones."""
    # Crear un resultado de escaneo con múltiples anotaciones
    scan_result = ScanResult(
        introduction="Se ha realizado un análisis de seguridad del código",
        status=ScanStatus.FAILED,
        number_of_issues=2,
        annotations=[
            Annotation(
                title="Ejecución de código arbitrario",
                description="La función eval puede ejecutar código arbitrario",
                severity="CRITICAL",
                path="app/main.py",
                line=10,
                summary="Uso de eval con entrada no sanitizada",
                code="eval(input())",
                recommendation="Evitar el uso de eval con entrada del usuario",
            ),
            Annotation(
                title="SQL Injection",
                description="Posible SQL Injection en consulta",
                severity="HIGH",
                path="app/database.py",
                line=25,
                summary="Consulta SQL con parámetros no sanitizados",
                code="query = f\"SELECT * FROM users WHERE id = {user_id}\"",
                recommendation="Usar consultas parametrizadas",
            ),
        ],
    )
    
    # Crear mocks para la API de GitHub
    mock_issue = Mock()
    mock_issue.html_url = "https://github.com/test-owner/test-repo/issues/1"
    
    mock_repo = Mock()
    mock_repo.create_issue.return_value = mock_issue
    
    mock_commit = Mock()
    mock_commit.commit.author.name = "Test Author"
    mock_repo.get_commit.return_value = mock_commit
    
    mock_github = Mock()
    mock_github.get_repo.return_value = mock_repo
    
    # Aplicar patch al constructor de Github
    with patch(GITHUB_MODULE, return_value=mock_github):
        # Crear servicio y ejecutar
        service = GithubOutputService(
            args=github_args, configuration_service=mock_config_service
        )
        result = service.execute(scan_result)
        
        # Verificar que se creó el issue con todas las anotaciones
        mock_repo.create_issue.assert_called_once()
        call_args = mock_repo.create_issue.call_args[1]
        
        # Verificar que ambas anotaciones están en el cuerpo
        body = call_args["body"]
        assert "1. Ejecución de código arbitrario" in body
        assert "2. SQL Injection" in body
        assert "CRITICAL" in body
        assert "HIGH" in body
        assert "app/main.py" in body
        assert "app/database.py" in body
        assert "Evitar el uso de eval" in body
        assert "Usar consultas parametrizadas" in body
        
        # Verificar el resultado
        assert isinstance(result, GithubOutputResult)
        assert result.issue_url == "https://github.com/test-owner/test-repo/issues/1"


def test_execute_with_error(
    mock_config_service, github_args, sample_scan_result
):
    """Test que verifica el manejo de errores en la API de GitHub."""
    # Crear mock que lanza una excepción
    mock_github = Mock()
    mock_github.get_repo.side_effect = Exception("API Error")
    
    # Aplicar patch al constructor de Github
    with patch(GITHUB_MODULE, return_value=mock_github):
        # Crear servicio
        service = GithubOutputService(
            args=github_args, configuration_service=mock_config_service
        )
        
        # Verificar que se propaga la excepción
        with pytest.raises(Exception) as excinfo:
            service.execute(sample_scan_result)
        
        assert "API Error" in str(excinfo.value) 