from unittest.mock import Mock, patch, mock_open
from datetime import datetime
import pytest
from titvo.app.scan.scan_use_case import RunScanUseCase
from titvo.app.scan.scan_entities import Scan, ScanStatus, Prompt, ScanResult
from titvo.app.task.task_entities import Task, TaskStatus, TaskSource
from titvo.app.hint.hint_entities import Hint


def test_run_scan_use_case():
    # Arrange
    mock_get_task_use_case = Mock()
    mock_mark_task_in_progress_use_case = Mock()
    mock_mark_task_completed_use_case = Mock()
    mock_mark_task_failed_use_case = Mock()
    mock_mark_task_error_use_case = Mock()
    mock_ai_service = Mock()
    mock_configuration_service = Mock()
    mock_hint_use_case = Mock()
    mock_file_fetcher_service_factory = Mock()
    mock_output_service_factory = Mock()
    mock_file_fetcher_service = Mock()
    mock_output_service = Mock()

    # Mock del task
    task = Task(
        id="task123",
        result={},
        args={"repository": "test-repo"},
        hint_id="hint123",
        scaned_files=0,
        created_at=datetime(2024, 1, 1),
        updated_at=datetime(2024, 1, 1),
        status=TaskStatus.PENDING,
        source=TaskSource.GITHUB,
    )

    # Mock del hint
    hint = Hint(
        id="hint123",
        name="hint123",
        slug="hint123",
        url="hint123",
        content="Este es un hint de prueba",
    )

    # Mock de ScanResult
    scan_result = ScanResult(
        introduction="Introducción del análisis",
        status=ScanStatus.WARNING,
        number_of_issues=2,
        annotations=[],
    )

    # Configurar comportamiento de los mocks
    mock_get_task_use_case.execute.return_value = task
    mock_hint_use_case.execute.return_value = hint
    mock_configuration_service.get_value.return_value = "system prompt de prueba"
    mock_file_fetcher_service_factory.create_file_fetcher_service.return_value = (
        mock_file_fetcher_service
    )
    mock_file_fetcher_service.fetch_files.return_value = ["file1.py", "file2.py"]
    mock_ai_service.execute.return_value = scan_result
    mock_output_service_factory.create_output_service.return_value = mock_output_service
    mock_output_service.execute.return_value = {"vulnerabilities": []}

    # Crear caso de uso
    use_case = RunScanUseCase(
        get_task_use_case=mock_get_task_use_case,
        mark_task_in_progress_use_case=mock_mark_task_in_progress_use_case,
        mark_task_completed_use_case=mock_mark_task_completed_use_case,
        mark_task_failed_use_case=mock_mark_task_failed_use_case,
        mark_task_error_use_case=mock_mark_task_error_use_case,
        ai_service=mock_ai_service,
        configuration_service=mock_configuration_service,
        hint_use_case=mock_hint_use_case,
        file_fetcher_service_factory=mock_file_fetcher_service_factory,
        output_service_factory=mock_output_service_factory,
        repo_files_path="/path/to/repo",
    )

    # Mock para open() en la lectura de archivos
    mock_file_content = "print('Hello, world!')"

    # Act
    with patch("builtins.open", mock_open(read_data=mock_file_content)):
        with patch("os.path.relpath", return_value="relative/path/to/file.py"):
            scan = Scan(id="task123")
            use_case.execute(scan)

    # Assert
    mock_get_task_use_case.execute.assert_called_once_with("task123")
    mock_mark_task_in_progress_use_case.execute.assert_called_once_with(task.id)
    mock_configuration_service.get_value.assert_called_once_with("scan_system_prompt")
    mock_hint_use_case.execute.assert_called_once_with(task.hint_id)
    mock_file_fetcher_service_factory.create_file_fetcher_service.assert_called_once_with(
        task.source
    )
    mock_file_fetcher_service.fetch_files.assert_called_once()

    # Verificar que el prompt se creó correctamente
    mock_ai_service.execute.assert_called_once()
    prompt_arg = mock_ai_service.execute.call_args[0][0]
    assert isinstance(prompt_arg, Prompt)
    assert prompt_arg.system_prompt == "system prompt de prueba"
    assert "Titvo soy el jefe de seguridad" in prompt_arg.user_prompt
    assert "Este es un hint de prueba" in prompt_arg.user_prompt
    assert "Archivo: relative/path/to/file.py" in prompt_arg.user_prompt
    assert "print('Hello, world!')" in prompt_arg.user_prompt

    # Verificar que se procesó el resultado correctamente
    mock_output_service_factory.create_output_service.assert_called_once_with(
        args=task.args,
        scan_id=scan.id,
        source=task.source,
    )
    mock_output_service.execute.assert_called_once_with(scan_result)

    # Verificar que se marcó la tarea como fallida (porque el status es WARNING)
    mock_mark_task_completed_use_case.execute.assert_called_once_with(
        task.id, {"vulnerabilities": []}, 2  # len(files)
    )
    mock_mark_task_error_use_case.assert_not_called()


def test_run_scan_use_case_with_error():
    # Arrange
    mock_get_task_use_case = Mock()
    mock_mark_task_in_progress_use_case = Mock()
    mock_mark_task_completed_use_case = Mock()
    mock_mark_task_failed_use_case = Mock()
    mock_mark_task_error_use_case = Mock()
    mock_ai_service = Mock()
    mock_configuration_service = Mock()
    mock_hint_use_case = Mock()
    mock_file_fetcher_service_factory = Mock()
    mock_output_service_factory = Mock()
    mock_file_fetcher_service = Mock()
    mock_output_service = Mock()
    # Mock del task
    task = Task(
        id="task123",
        result={},
        args={"repository": "test-repo"},
        hint_id="hint123",
        scaned_files=0,
        created_at=datetime(2024, 1, 1),
        updated_at=datetime(2024, 1, 1),
        status=TaskStatus.PENDING,
        source=TaskSource.GITHUB,
    )

    # Mock del hint
    hint = Hint(
        id="hint123",
        name="hint123",
        slug="hint123",
        url="hint123",
        content="Este es un hint de prueba",
    )

    # Mock de ScanResult con ERROR
    scan_result = ScanResult(
        introduction="Error en el análisis",
        status=ScanStatus.FAILED,
        number_of_issues=0,
        annotations=[],
    )

    # Configurar comportamiento de los mocks
    mock_get_task_use_case.execute.return_value = task
    mock_hint_use_case.execute.return_value = hint
    mock_configuration_service.get_value.return_value = "system prompt de prueba"
    mock_file_fetcher_service_factory.create_file_fetcher_service.return_value = (
        mock_file_fetcher_service
    )
    mock_file_fetcher_service.fetch_files.return_value = ["file1.py"]
    mock_ai_service.execute.return_value = scan_result
    mock_output_service_factory.create_output_service.return_value = mock_output_service
    mock_output_service.execute.return_value = {"vulnerabilities": []}

    # Crear caso de uso
    use_case = RunScanUseCase(
        get_task_use_case=mock_get_task_use_case,
        mark_task_in_progress_use_case=mock_mark_task_in_progress_use_case,
        mark_task_completed_use_case=mock_mark_task_completed_use_case,
        mark_task_failed_use_case=mock_mark_task_failed_use_case,
        mark_task_error_use_case=mock_mark_task_error_use_case,
        ai_service=mock_ai_service,
        configuration_service=mock_configuration_service,
        hint_use_case=mock_hint_use_case,
        file_fetcher_service_factory=mock_file_fetcher_service_factory,
        output_service_factory=mock_output_service_factory,
        repo_files_path="/path/to/repo",
    )

    # Act
    with patch("builtins.open", mock_open(read_data="print('API_KEY=1234567890')")):
        with patch("os.path.relpath", return_value="file1.py"):
            scan = Scan(id=task.id)
            use_case.execute(scan)

    # Assert
    mock_get_task_use_case.execute.assert_called_once_with("task123")
    mock_mark_task_in_progress_use_case.execute.assert_called_once_with(task.id)
    mock_configuration_service.get_value.assert_called_once_with("scan_system_prompt")
    mock_hint_use_case.execute.assert_called_once_with(task.hint_id)
    mock_file_fetcher_service_factory.create_file_fetcher_service.assert_called_once_with(
        task.source
    )
    mock_file_fetcher_service.fetch_files.assert_called_once()
    
    # Verificar que se creó el servicio de salida con los parámetros correctos
    mock_output_service_factory.create_output_service.assert_called_once_with(
        args=task.args,
        scan_id=scan.id,
        source=task.source,
    )
    
    # Verificar que se marcó la tarea como fallida (porque el status es FAILED)
    mock_mark_task_failed_use_case.execute.assert_called_once_with(
        task.id, {"vulnerabilities": []}, 1  # len(files)
    )
    mock_mark_task_error_use_case.assert_not_called()


def test_run_scan_use_case_with_exception():
    # Arrange
    mock_get_task_use_case = Mock()
    mock_mark_task_in_progress_use_case = Mock()
    mock_mark_task_completed_use_case = Mock()
    mock_mark_task_failed_use_case = Mock()
    mock_mark_task_error_use_case = Mock()
    mock_ai_service = Mock()
    mock_configuration_service = Mock()
    mock_hint_use_case = Mock()
    mock_file_fetcher_service_factory = Mock()
    mock_output_service_factory = Mock()
    
    # Mock del task
    task = Task(
        id="task123",
        result={},
        args={"repository": "test-repo"},
        hint_id="hint123",
        scaned_files=0,
        created_at=datetime(2024, 1, 1),
        updated_at=datetime(2024, 1, 1),
        status=TaskStatus.PENDING,
        source=TaskSource.GITHUB,
    )
    
    # Simular una excepción en algún punto del proceso
    # En este caso, hacemos que get_hint_use_case lance una excepción
    mock_get_task_use_case.execute.return_value = task
    mock_hint_use_case.execute.side_effect = Exception("Error al obtener el hint")
    
    # Crear caso de uso
    use_case = RunScanUseCase(
        get_task_use_case=mock_get_task_use_case,
        mark_task_in_progress_use_case=mock_mark_task_in_progress_use_case,
        mark_task_completed_use_case=mock_mark_task_completed_use_case,
        mark_task_failed_use_case=mock_mark_task_failed_use_case,
        mark_task_error_use_case=mock_mark_task_error_use_case,
        ai_service=mock_ai_service,
        configuration_service=mock_configuration_service,
        hint_use_case=mock_hint_use_case,
        file_fetcher_service_factory=mock_file_fetcher_service_factory,
        output_service_factory=mock_output_service_factory,
        repo_files_path="/path/to/repo",
    )
    
    # Act & Assert - Verificar que la excepción es propagada
    with pytest.raises(Exception) as excinfo:
        scan = Scan(id="task123")
        use_case.execute(scan)
    
    # Verificar que la excepción capturada es la esperada
    assert str(excinfo.value) == "Error al obtener el hint"
    
    # Verificar que se marcó la tarea con error antes de propagar la excepción
    mock_mark_task_error_use_case.execute.assert_called_once_with(task.id)
    
    # Verificar que se ejecutaron los pasos previos a la excepción
    mock_get_task_use_case.execute.assert_called_once_with("task123")
    mock_mark_task_in_progress_use_case.execute.assert_called_once_with(task.id)
    mock_configuration_service.get_value.assert_called_once_with("scan_system_prompt")
    mock_hint_use_case.execute.assert_called_once_with(task.hint_id)
    
    # Verificar que no se ejecutaron los pasos posteriores a la excepción
    mock_file_fetcher_service_factory.create_file_fetcher_service.assert_not_called()
    mock_mark_task_completed_use_case.assert_not_called()
    mock_mark_task_failed_use_case.assert_not_called()
