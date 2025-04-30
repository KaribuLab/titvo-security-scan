from unittest.mock import Mock
from datetime import datetime
from titvo.app.task.task_use_case import (
    MarkTaskCompletedUseCase,
    GetTaskUseCase,
    MarkTaskInProgressUseCase,
    MarkTaskFailedUseCase,
    MarkTaskErrorUseCase,
)
from titvo.app.task.task_entities import Task, TaskStatus, TaskSource


def test_mark_task_completed_use_case():
    # Arrange
    mock_task_repository = Mock()
    task_id = "abc123"

    # Mock Task object
    task = Task(
        id=task_id,
        result={},
        args={"some": "arg"},
        hint_id="hint123",
        scaned_files=0,
        created_at=datetime(2024, 1, 1),
        updated_at=datetime(2024, 1, 1),
        status=TaskStatus.PENDING,
        source=TaskSource.GITHUB,
    )

    # Mock behavior del repository
    mock_task_repository.get_task.return_value = task
    mock_task_repository.update_task.return_value = task  # Devuelve el task actualizado

    # Caso de uso
    use_case = MarkTaskCompletedUseCase(mock_task_repository)
    result_data = {"vulnerabilities": []}
    scanned_files = 5

    # Act
    updated_task = use_case.execute(task_id, result_data, scanned_files)

    # Assert
    assert updated_task.status == TaskStatus.COMPLETED
    assert updated_task.result == result_data
    assert updated_task.scaned_files == scanned_files
    assert (
        updated_task.updated_at > task.created_at
    )  # Verifica que updated_at fue actualizado

    mock_task_repository.get_task.assert_called_once_with(task_id)
    mock_task_repository.update_task.assert_called_once_with(task)


def test_get_task_use_case():
    # Arrange
    mock_task_repository = Mock()
    task_id = "abc123"

    # Mock Task object
    expected_task = Task(
        id=task_id,
        result={},
        args={"some": "arg"},
        hint_id="hint123",
        scaned_files=0,
        created_at=datetime(2024, 1, 1),
        updated_at=datetime(2024, 1, 1),
        status=TaskStatus.PENDING,
        source=TaskSource.GITHUB,
    )

    # Mock behavior del repository
    mock_task_repository.get_task.return_value = expected_task

    # Caso de uso
    use_case = GetTaskUseCase(mock_task_repository)

    # Act
    task = use_case.execute(task_id)

    # Assert
    assert task == expected_task
    mock_task_repository.get_task.assert_called_once_with(task_id)


def test_mark_task_in_progress_use_case():
    # Arrange
    mock_task_repository = Mock()
    task_id = "abc123"

    # Mock Task object
    task = Task(
        id=task_id,
        result={},
        args={"some": "arg"},
        hint_id="hint123",
        scaned_files=0,
        created_at=datetime(2024, 1, 1),
        updated_at=datetime(2024, 1, 1),
        status=TaskStatus.PENDING,
        source=TaskSource.GITHUB,
    )

    # Mock behavior del repository
    mock_task_repository.get_task.return_value = task
    mock_task_repository.update_task.return_value = task

    # Caso de uso
    use_case = MarkTaskInProgressUseCase(mock_task_repository)

    # Act
    updated_task = use_case.execute(task_id)

    # Assert
    assert updated_task.status == TaskStatus.IN_PROGRESS
    assert updated_task.updated_at > task.created_at

    mock_task_repository.get_task.assert_called_once_with(task_id)
    mock_task_repository.update_task.assert_called_once_with(task)


def test_mark_task_failed_use_case():
    # Arrange
    mock_task_repository = Mock()
    task_id = "abc123"

    # Mock Task object
    task = Task(
        id=task_id,
        result={},
        args={"some": "arg"},
        hint_id="hint123",
        scaned_files=0,
        created_at=datetime(2024, 1, 1),
        updated_at=datetime(2024, 1, 1),
        status=TaskStatus.IN_PROGRESS,
        source=TaskSource.GITHUB,
    )

    # Mock behavior del repository
    mock_task_repository.get_task.return_value = task
    mock_task_repository.update_task.return_value = task

    # Caso de uso
    use_case = MarkTaskFailedUseCase(mock_task_repository)
    result_data = {"error": "Some failure occurred"}
    scanned_files = 3

    # Act
    updated_task = use_case.execute(task_id, result_data, scanned_files)

    # Assert
    assert updated_task.status == TaskStatus.FAILED
    assert updated_task.result == result_data
    assert updated_task.scaned_files == scanned_files
    assert updated_task.updated_at > task.created_at

    mock_task_repository.get_task.assert_called_once_with(task_id)
    mock_task_repository.update_task.assert_called_once_with(task)


def test_mark_task_error_use_case():
    # Arrange
    mock_task_repository = Mock()
    task_id = "abc123"

    # Mock Task object
    task = Task(
        id=task_id,
        result={},
        args={"some": "arg"},
        hint_id="hint123",
        scaned_files=0,
        created_at=datetime(2024, 1, 1),
        updated_at=datetime(2024, 1, 1),
        status=TaskStatus.IN_PROGRESS,
        source=TaskSource.GITHUB,
    )

    # Mock behavior del repository
    mock_task_repository.get_task.return_value = task
    mock_task_repository.update_task.return_value = task

    # Caso de uso
    use_case = MarkTaskErrorUseCase(mock_task_repository)

    # Act
    updated_task = use_case.execute(task_id)

    # Assert
    assert updated_task.status == TaskStatus.ERROR
    assert updated_task.updated_at > task.created_at

    mock_task_repository.get_task.assert_called_once_with(task_id)
    mock_task_repository.update_task.assert_called_once_with(task)
