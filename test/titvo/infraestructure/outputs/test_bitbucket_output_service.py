import os
import json
from unittest.mock import patch, Mock, mock_open
import pytest
from titvo.infraestructure.outputs.bitbucket_output_service import (
    BitbucketOutputService,
    BitbucketOutputArgs,
    BitbucketOutputResult,
    ACCESS_TOKEN_URL,
)
from titvo.app.scan.scan_entities import ScanResult, Annotation, ScanStatus
from titvo.app.task.task_entities import TaskSource

# Constantes para los módulos que haremos patch
REQUESTS_MODULE = "titvo.infraestructure.outputs.bitbucket_output_service.requests"
HTML_REPORT_MODULE = (
    "titvo.infraestructure.outputs.bitbucket_output_service.create_issue_html"
)
OS_MAKEDIRS = "titvo.infraestructure.outputs.bitbucket_output_service.os.makedirs"
OPEN_MODULE = "titvo.infraestructure.outputs.bitbucket_output_service.open"

# pylint: disable=redefined-outer-name


@pytest.fixture
def mock_config_service():
    """Fixture que crea un mock del servicio de configuración."""
    mock_service = Mock()
    mock_service.get_secret.return_value = json.dumps(
        {"key": "test-key", "secret": "test-secret"}
    )
    # pylint: disable=unnecessary-lambda
    mock_service.get_value.side_effect = lambda key: {
        "report_bucket_domain": "https://example.com",
        "report_bucket_name": "test-bucket",
        "report_html_template": "<html><body>{{content}}</body></html>",
    }.get(key)
    # pylint: enable=unnecessary-lambda
    return mock_service


@pytest.fixture
def mock_storage_service():
    """Fixture que crea un mock del servicio de almacenamiento."""
    mock_service = Mock()
    return mock_service


@pytest.fixture
def bitbucket_args():
    """Fixture que crea argumentos para el BitbucketOutputService."""
    return BitbucketOutputArgs(
        bitbucket_workspace="test-workspace",
        bitbucket_repo_slug="test-repo",
        bitbucket_commit="abcdef1234567890",
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


@pytest.fixture
def template_path():
    """Fixture que crea una ruta de plantilla para pruebas."""
    return "/tmp/templates"


@pytest.fixture
def scan_id():
    """Fixture que crea un ID de escaneo para pruebas."""
    return "test-scan-123"


def test_execute_create_report(
    mock_config_service,
    mock_storage_service,
    bitbucket_args,
    sample_scan_result,
    template_path,
    scan_id,
):
    """Test que verifica la creación de informes en Bitbucket."""
    # Crear mock para las respuestas de requests
    mock_token_response = Mock()
    mock_token_response.json.return_value = {"access_token": "test-token"}

    mock_report_response = Mock()
    mock_create_annotation_response = Mock()

    # Configurar el mock de requests.post/put para devolver las respuestas simuladas
    mock_requests = Mock()
    mock_requests.post.side_effect = [
        mock_token_response,
        mock_create_annotation_response,
    ]
    mock_requests.put.return_value = mock_report_response

    # Mock para create_issue_html
    mock_html_content = "<html>Test Report</html>"
    mock_create_html = Mock(return_value=mock_html_content)

    # Aplicar los patches
    with patch(REQUESTS_MODULE, mock_requests), patch(
        HTML_REPORT_MODULE, mock_create_html
    ), patch(OS_MAKEDIRS) as mock_makedirs, patch(
        OPEN_MODULE, mock_open()
    ) as mock_file:

        # Crear servicio y ejecutar
        service = BitbucketOutputService(
            args=bitbucket_args,
            configuration_service=mock_config_service,
            storage_service=mock_storage_service,
            template_path=template_path,
            scan_id=scan_id,
            source=TaskSource.BITBUCKET,
        )
        result = service.execute(sample_scan_result)

        # Verificar que se obtuvo el token de acceso
        mock_requests.post.assert_any_call(
            ACCESS_TOKEN_URL,
            data={
                "client_id": "test-key",
                "client_secret": "test-secret",
                "grant_type": "client_credentials",
            },
            timeout=30,
        )

        # Verificar la creación del informe
        mock_requests.put.assert_called_once()
        args, kwargs = mock_requests.put.call_args
        report_url = args[0]
        assert bitbucket_args.bitbucket_workspace in report_url
        assert bitbucket_args.bitbucket_repo_slug in report_url
        assert bitbucket_args.bitbucket_commit in report_url

        # Verificar el payload del informe
        payload = kwargs["json"]
        assert payload["title"] == "Titvo Security Scan"
        assert payload["report_type"] == "SECURITY"
        assert payload["result"] == sample_scan_result.status

        # Verificar la creación de anotaciones
        mock_requests.post.assert_any_call(
            mock_requests.put.call_args[0][0] + "/annotations",
            headers=kwargs["headers"],
            json=[
                {
                    "external_id": mock_requests.post.call_args[1]["json"][0][
                        "external_id"
                    ],
                    "annotation_type": "VULNERABILITY",
                    "title": "Ejecución de código arbitrario",
                    "description": "La función eval puede ejecutar código arbitrario",
                    "severity": "CRITICAL",
                    "path": "app/main.py",
                    "line": 10,
                }
            ],
            timeout=30,
        )

        # Verificar la creación del directorio y los archivos HTML
        mock_makedirs.assert_called_once_with(template_path, exist_ok=True)

        # Verificar escritura de la plantilla
        mock_file.assert_any_call(
            os.path.join(template_path, "report.html"), "w", encoding="utf-8"
        )
        mock_file().write.assert_any_call("<html><body>{{content}}</body></html>")

        # Verificar generación del reporte HTML
        mock_create_html.assert_called_once_with(
            sample_scan_result, template_path=template_path, template_name="report.html"
        )

        # Verificar escritura del reporte generado
        mock_file.assert_any_call(
            os.path.join(template_path, f"{scan_id}.html"), "w", encoding="utf-8"
        )
        mock_file().write.assert_any_call(mock_html_content)

        # Verificar la carga del archivo
        mock_storage_service.upload_file.assert_called_once()
        upload_request = mock_storage_service.upload_file.call_args[0][0]
        assert upload_request.container_name == "test-bucket"
        assert upload_request.input_path == os.path.join(
            template_path, f"{scan_id}.html"
        )
        assert (
            upload_request.file_path
            == f"scm/{TaskSource.BITBUCKET.value}/scan/{scan_id}.html"
        )

        # Verificar el resultado
        assert isinstance(result, BitbucketOutputResult)
        assert (
            result.report_url
            == f"https://example.com/scm/{TaskSource.BITBUCKET.value}/scan/{scan_id}.html"
        )


def test_execute_with_api_error(
    mock_config_service,
    mock_storage_service,
    bitbucket_args,
    sample_scan_result,
    template_path,
    scan_id,
):
    """Test que verifica el manejo de errores en la API de Bitbucket."""
    # Configurar el mock de requests para lanzar una excepción
    mock_requests = Mock()
    mock_requests.post.side_effect = Exception("API Error")

    # Aplicar los patches
    with patch(REQUESTS_MODULE, mock_requests), patch(HTML_REPORT_MODULE), patch(
        OS_MAKEDIRS
    ), patch(OPEN_MODULE, mock_open()):

        # Crear servicio
        service = BitbucketOutputService(
            args=bitbucket_args,
            configuration_service=mock_config_service,
            storage_service=mock_storage_service,
            template_path=template_path,
            scan_id=scan_id,
            source=TaskSource.BITBUCKET,
        )

        # Verificar que se propaga la excepción
        with pytest.raises(Exception) as excinfo:
            service.execute(sample_scan_result)

        assert "API Error" in str(excinfo.value)


def test_execute_with_missing_credentials(
    bitbucket_args, sample_scan_result, template_path, scan_id
):
    """Test que verifica el manejo de credenciales faltantes."""
    # Crear mock del servicio de configuración que devuelve None para las credenciales
    mock_config = Mock()
    mock_config.get_secret.return_value = None

    mock_storage = Mock()

    # Crear servicio
    service = BitbucketOutputService(
        args=bitbucket_args,
        configuration_service=mock_config,
        storage_service=mock_storage,
        template_path=template_path,
        scan_id=scan_id,
        source=TaskSource.BITBUCKET,
    )

    # Verificar que se lanza una excepción
    with pytest.raises(ValueError) as excinfo:
        service.execute(sample_scan_result)

    assert "Client credentials not found" in str(excinfo.value)


def test_execute_multiple_annotations(
    mock_config_service, mock_storage_service, bitbucket_args, template_path, scan_id
):
    """Test que verifica la creación de informes con múltiples anotaciones."""
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
                code='query = f"SELECT * FROM users WHERE id = {user_id}"',
                recommendation="Usar consultas parametrizadas",
            ),
        ],
    )

    # Crear mock para las respuestas de requests
    mock_token_response = Mock()
    mock_token_response.json.return_value = {"access_token": "test-token"}

    mock_report_response = Mock()
    mock_create_annotation_response = Mock()

    # Configurar el mock de requests
    mock_requests = Mock()
    mock_requests.post.side_effect = [
        mock_token_response,
        mock_create_annotation_response,
    ]
    mock_requests.put.return_value = mock_report_response

    # Aplicar los patches
    with patch(REQUESTS_MODULE, mock_requests), patch(
        HTML_REPORT_MODULE, return_value="<html>Test</html>"
    ), patch(OS_MAKEDIRS), patch(OPEN_MODULE, mock_open()):

        # Crear servicio y ejecutar
        service = BitbucketOutputService(
            args=bitbucket_args,
            configuration_service=mock_config_service,
            storage_service=mock_storage_service,
            template_path=template_path,
            scan_id=scan_id,
            source=TaskSource.BITBUCKET,
        )
        service.execute(scan_result)

        # Verificar que se crearon anotaciones para ambos problemas
        annotations = mock_requests.post.call_args[1]["json"]
        assert len(annotations) == 2
        assert annotations[0]["title"] == "Ejecución de código arbitrario"
        assert annotations[0]["severity"] == "CRITICAL"
        assert annotations[1]["title"] == "SQL Injection"
        assert annotations[1]["severity"] == "HIGH"
