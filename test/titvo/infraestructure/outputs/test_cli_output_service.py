import os
from unittest.mock import patch, Mock, mock_open
import pytest
from titvo.infraestructure.outputs.cli_output_service import (
    CliOutputService,
    CliOutputResult,
    CliOutputArgs,
)
from titvo.app.scan.scan_entities import ScanResult, Annotation, ScanStatus
from titvo.app.task.task_entities import TaskSource

# Constantes para los módulos que haremos patch
HTML_REPORT_MODULE = (
    "titvo.infraestructure.outputs.cli_output_service.create_issue_html"
)
OS_MAKEDIRS = "titvo.infraestructure.outputs.cli_output_service.os.makedirs"
OPEN_MODULE = "titvo.infraestructure.outputs.cli_output_service.open"

# pylint: disable=redefined-outer-name


@pytest.fixture
def mock_config_service():
    """Fixture que crea un mock del servicio de configuración."""
    mock_service = Mock()
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
def sample_scan_result():
    """Fixture que crea un resultado de escaneo de prueba."""
    return ScanResult(
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


@pytest.fixture
def cli_args():
    """Fixture que crea argumentos para el CliOutputService."""
    return CliOutputArgs(
        batch_id="test-batch-123",
        repository_url="https://github.com/test/repo"
    )


def test_execute(
    mock_config_service,
    mock_storage_service,
    sample_scan_result,
    template_path,
    scan_id,
    cli_args,
):
    """Test que verifica la generación y carga del informe HTML."""
    # Mock para create_issue_html
    mock_html_content = "<html>Test Report</html>"
    mock_create_html = Mock(return_value=mock_html_content)

    # Aplicar los patches
    with patch(HTML_REPORT_MODULE, mock_create_html), patch(
        OS_MAKEDIRS
    ) as mock_makedirs, patch(OPEN_MODULE, mock_open()) as mock_file:

        # Crear servicio y ejecutar
        service = CliOutputService(
            args=cli_args,
            configuration_service=mock_config_service,
            storage_service=mock_storage_service,
            template_path=template_path,
            scan_id=scan_id,
            source=TaskSource.CLI,
        )
        result = service.execute(sample_scan_result)

        # Verificar la creación del directorio
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
            == f"scm/{TaskSource.CLI.value}/scan/{scan_id}.html"
        )
        assert upload_request.content_type == "text/html; charset=utf-8"

        # Verificar el resultado
        assert isinstance(result, CliOutputResult)
        assert (
            result.report_url
            == f"https://example.com/scm/{TaskSource.CLI.value}/scan/{scan_id}.html"
        )
        assert result.to_dict() == {
            "report_url": f"https://example.com/scm/{TaskSource.CLI.value}/scan/{scan_id}.html"
        }


def test_execute_with_different_source(
    mock_config_service,
    mock_storage_service,
    sample_scan_result,
    template_path,
    scan_id,
    cli_args,
):
    """Test que verifica el uso de diferentes fuentes de tarea."""
    # Aplicar los patches
    with patch(HTML_REPORT_MODULE, return_value="<html>Test</html>"), patch(
        OS_MAKEDIRS
    ), patch(OPEN_MODULE, mock_open()):

        # Crear servicio con otra fuente
        service = CliOutputService(
            args=cli_args,
            configuration_service=mock_config_service,
            storage_service=mock_storage_service,
            template_path=template_path,
            scan_id=scan_id,
            source=TaskSource.GITHUB,
        )
        result = service.execute(sample_scan_result)

        # Verificar la ruta con la fuente correcta
        upload_request = mock_storage_service.upload_file.call_args[0][0]
        assert (
            upload_request.file_path
            == f"scm/{TaskSource.GITHUB.value}/scan/{scan_id}.html"
        )
        assert (
            result.report_url
            == f"https://example.com/scm/{TaskSource.GITHUB.value}/scan/{scan_id}.html"
        )


def test_execute_with_error_creating_directory(
    mock_config_service,
    mock_storage_service,
    sample_scan_result,
    template_path,
    scan_id,
    cli_args,
):
    """Test que verifica el manejo de errores al crear directorios."""
    # Configurar makedirs para lanzar excepción
    mock_makedirs = Mock(side_effect=PermissionError("Permission denied"))

    # Aplicar los patches
    with patch(HTML_REPORT_MODULE), patch(OS_MAKEDIRS, mock_makedirs), patch(
        OPEN_MODULE, mock_open()
    ):

        # Crear servicio
        service = CliOutputService(
            args=cli_args,
            configuration_service=mock_config_service,
            storage_service=mock_storage_service,
            template_path=template_path,
            scan_id=scan_id,
            source=TaskSource.CLI,
        )

        # Verificar que se propaga la excepción
        with pytest.raises(PermissionError) as excinfo:
            service.execute(sample_scan_result)

        assert "Permission denied" in str(excinfo.value)


def test_execute_with_missing_configuration(
    mock_storage_service, sample_scan_result, template_path, scan_id, cli_args
):
    """Test que verifica el manejo de configuración faltante."""
    # Crear mock del servicio de configuración que devuelve None
    mock_config = Mock()
    mock_config.get_value.return_value = None

    # Aplicar los patches
    with patch(HTML_REPORT_MODULE), patch(OS_MAKEDIRS), patch(OPEN_MODULE, mock_open()):

        # Crear servicio
        service = CliOutputService(
            args=cli_args,
            configuration_service=mock_config,
            storage_service=mock_storage_service,
            template_path=template_path,
            scan_id=scan_id,
            source=TaskSource.CLI,
        )

        # Ejecutar y verificar que no hay errores aunque los valores sean None
        result = service.execute(sample_scan_result)

        # Verificar que el resultado contiene valores None
        assert result.report_url == "None/scm/cli/scan/test-scan-123.html"
