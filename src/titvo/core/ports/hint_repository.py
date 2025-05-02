from abc import ABC, abstractmethod
from titvo.app.hint.hint_entities import Hint


class HintRepository(ABC):
    @abstractmethod
    def get_hint(self, hint_id: str) -> Hint | None:
        pass
