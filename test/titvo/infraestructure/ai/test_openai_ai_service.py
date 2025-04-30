from unittest.mock import patch, Mock
import pytest
from langchain_core.messages import SystemMessage, HumanMessage
from titvo.infraestructure.ai.openai_ai_service import (
    OpenAIAiService,
    SecurityReport,
    ReportAnnotation,
)
from titvo.app.scan.scan_entities import Prompt, ScanStatus

# Constantes para los módulos que haremos patch
LANGCHAIN_INIT_CHAT_MODEL = "titvo.infraestructure.ai.openai_ai_service.init_chat_model"

# pylint: disable=redefined-outer-name


@pytest.fixture
def mock_config_service():
    """Fixture que crea un mock del servicio de configuración."""
    mock_service = Mock()
    mock_service.get_secret.return_value = "test-api-key"
    mock_service.get_value.return_value = "gpt-4"
    return mock_service


@pytest.fixture
def sample_prompt():
    """Fixture que crea una instancia de Prompt para pruebas."""
    return Prompt(
        system_prompt="Analiza este código en busca de vulnerabilidades",
        user_prompt="def vulnerable_function():\n    eval(input())",
    )


@pytest.fixture
def sample_security_report():
    """Fixture que crea un informe de seguridad de ejemplo."""
    return SecurityReport(
        introduction="Se ha realizado un análisis de seguridad del código proporcionado",
        status="FAILED",
        number_of_issues=1,
        annotations=[
            ReportAnnotation(
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


def test_execute(mock_config_service, sample_prompt, sample_security_report):
    """Test para verificar que el método execute funciona correctamente."""
    # Crear mocks para langchain
    mock_structured_output = Mock()
    mock_structured_output.invoke.return_value = sample_security_report

    mock_llm = Mock()
    mock_llm.with_structured_output.return_value = mock_structured_output

    # Patch de la función init_chat_model
    with patch(LANGCHAIN_INIT_CHAT_MODEL, return_value=mock_llm):
        # Crear servicio y ejecutar
        service = OpenAIAiService(configuration_service=mock_config_service)
        result = service.execute(sample_prompt)

        # Verificar llamadas al servicio de configuración
        mock_config_service.get_secret.assert_called_once_with("open_ai_api_key")
        mock_config_service.get_value.assert_called_once_with("open_ai_model")

        # Verificar que se inicializa el modelo con los parámetros correctos
        mock_llm.with_structured_output.assert_called_once_with(SecurityReport)

        # Verificar que se invoca el LLM con los mensajes correctos
        messages = mock_structured_output.invoke.call_args[0][0]
        assert len(messages) == 2
        assert isinstance(messages[0], SystemMessage)
        assert messages[0].content == sample_prompt.system_prompt
        assert isinstance(messages[1], HumanMessage)
        assert messages[1].content == sample_prompt.user_prompt

        # Verificar el resultado
        assert result.introduction == sample_security_report.introduction
        assert result.status == ScanStatus(sample_security_report.status)
        assert result.number_of_issues == sample_security_report.number_of_issues
        assert len(result.annotations) == 1

        # Verificar la anotación
        annotation = result.annotations[0]
        report_annotation = sample_security_report.annotations[0]
        assert annotation.title == report_annotation.title
        assert annotation.description == report_annotation.description
        assert annotation.severity == report_annotation.severity
        assert annotation.path == report_annotation.path
        assert annotation.line == report_annotation.line
        assert annotation.summary == report_annotation.summary
        assert annotation.code == report_annotation.code
        assert annotation.recommendation == report_annotation.recommendation


def test_execute_error_handling(mock_config_service, sample_prompt):
    """Test para verificar el manejo de errores en execute."""
    # Configurar mock para lanzar una excepción
    mock_llm = Mock()
    mock_llm.with_structured_output.side_effect = Exception("API Error")

    # Patch de la función init_chat_model
    with patch(LANGCHAIN_INIT_CHAT_MODEL, return_value=mock_llm):
        # Crear servicio
        service = OpenAIAiService(configuration_service=mock_config_service)

        # Verificar que se propaga la excepción
        with pytest.raises(Exception) as excinfo:
            service.execute(sample_prompt)

        assert "API Error" in str(excinfo.value)


def test_scan_status_mapping(mock_config_service, sample_prompt):
    """Test para verificar la conversión correcta del estado del escaneo."""
    # Crear informes con diferentes estados
    status_reports = {
        "SUCCESS": SecurityReport(
            introduction="Análisis completado sin problemas",
            status="SUCCESS",
            number_of_issues=0,
            annotations=[],
        ),
        "WARNING": SecurityReport(
            introduction="Análisis completado con advertencias",
            status="WARNING",
            number_of_issues=1,
            annotations=[
                ReportAnnotation(
                    title="Problema menor",
                    description="Posible mejora",
                    severity="LOW",
                    path="app/util.py",
                    line=15,
                    summary="Mejora sugerida",
                    code="print(data)",
                    recommendation="Usar logging",
                )
            ],
        ),
        "FAILED": SecurityReport(
            introduction="Análisis completado con problemas críticos",
            status="FAILED",
            number_of_issues=1,
            annotations=[
                ReportAnnotation(
                    title="Problema crítico",
                    description="Vulnerabilidad severa",
                    severity="CRITICAL",
                    path="app/auth.py",
                    line=25,
                    summary="Credenciales hardcodeadas",
                    code="password = '123456'",
                    recommendation="Usar variables de entorno",
                )
            ],
        ),
    }

    for status, report in status_reports.items():
        # Configurar mocks
        mock_structured_output = Mock()
        mock_structured_output.invoke.return_value = report

        mock_llm = Mock()
        mock_llm.with_structured_output.return_value = mock_structured_output

        # Patch de la función init_chat_model
        with patch(LANGCHAIN_INIT_CHAT_MODEL, return_value=mock_llm):
            # Crear servicio y ejecutar
            service = OpenAIAiService(configuration_service=mock_config_service)
            result = service.execute(sample_prompt)

            # Verificar que el estado se mapea correctamente
            assert result.status == ScanStatus(status)
            assert result.number_of_issues == report.number_of_issues
