from abc import ABC, abstractmethod
from titvo.app.hint.hint_entities import Hint


class HintRepository(ABC):
    @abstractmethod
    def get_hint(self, repository_id: str) -> Hint:
        pass
