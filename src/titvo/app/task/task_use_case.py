from titvo.core.ports.task_repository import TaskRepository
from titvo.app.task.task_entities import Task


class GetTaskUseCase:
    def __init__(self, task_repository: TaskRepository):
        self.task_repository = task_repository

    def execute(self, task_id: str) -> Task:
        return self.task_repository.get_task(task_id)


class MarkTaskInProgressUseCase:
    def __init__(self, task_repository: TaskRepository):
        self.task_repository = task_repository

    def execute(self, task_id: str) -> Task:
        task = self.task_repository.get_task(task_id)
        task.mark_in_progress()
        return self.task_repository.update_task(task)


class MarkTaskCompletedUseCase:
    def __init__(self, task_repository: TaskRepository):
        self.task_repository = task_repository

    def execute(self, task_id: str, result: dict, scaned_files: int) -> Task:
        task = self.task_repository.get_task(task_id)
        task.mark_completed(result, scaned_files)
        return self.task_repository.update_task(task)


class MarkTaskFailedUseCase:
    def __init__(self, task_repository: TaskRepository):
        self.task_repository = task_repository

    def execute(self, task_id: str, result: dict, scaned_files: int) -> Task:
        task = self.task_repository.get_task(task_id)
        task.mark_failed(result, scaned_files)
        return self.task_repository.update_task(task)


class MarkTaskErrorUseCase:
    def __init__(self, task_repository: TaskRepository):
        self.task_repository = task_repository

    def execute(self, task_id: str) -> Task:
        task = self.task_repository.get_task(task_id)
        task.mark_error()
        return self.task_repository.update_task(task)
