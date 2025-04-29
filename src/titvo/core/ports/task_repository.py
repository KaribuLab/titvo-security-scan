from abc import ABC, abstractmethod
from titvo.app.task.task_entities import Task


class TaskRepository(ABC):
    @abstractmethod
    def get_task(self, task_id: str) -> Task:
        pass

    @abstractmethod
    def update_task(self, task: Task) -> Task:
        pass
