from unittest.mock import Mock
import pytest
from titvo.infraestructure.ai.ai_service_factory import create_ai_service
from titvo.infraestructure.ai.openai_ai_service import OpenAIAiService
from titvo.infraestructure.ai.anthropic_ai_service import AnthropicAiService
from titvo.infraestructure.ai.google_ai_service import GoogleAiService
from titvo.infraestructure.ai.open_router_ai_service import OpenRouterAiService

# pylint: disable=redefined-outer-name


@pytest.fixture
def mock_config_service():
    return Mock()


def test_create_openai_service(mock_config_service):
    mock_config_service.get_value.return_value = "openai"
    result = create_ai_service(mock_config_service)
    assert isinstance(result, OpenAIAiService)


def test_create_anthropic_service(mock_config_service):
    mock_config_service.get_value.return_value = "anthropic"
    result = create_ai_service(mock_config_service)
    assert isinstance(result, AnthropicAiService)


def test_create_google_service(mock_config_service):
    mock_config_service.get_value.return_value = "google"
    result = create_ai_service(mock_config_service)
    assert isinstance(result, GoogleAiService)


def test_create_openrouter_service(mock_config_service):
    mock_config_service.get_value.return_value = "openrouter"
    result = create_ai_service(mock_config_service)
    assert isinstance(result, OpenRouterAiService)


def test_create_unsupported_provider(mock_config_service):
    mock_config_service.get_value.return_value = "unknown"
    with pytest.raises(ValueError):
        create_ai_service(mock_config_service)
