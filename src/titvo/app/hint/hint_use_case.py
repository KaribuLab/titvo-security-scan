from titvo.core.ports.hint_repository import HintRepository
from titvo.app.hint.hint_entities import Hint


class GetHintUseCase:
    def __init__(self, hint_repository: HintRepository):
        self.hint_repository = hint_repository

    def execute(self, hint_id: str) -> Hint:
        return self.hint_repository.get_hint(hint_id)
