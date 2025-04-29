from abc import ABC, abstractmethod


class ConfigurationService(ABC):
    @abstractmethod
    def get_value(self, name: str) -> str:
        pass

    @abstractmethod
    def get_secret(self, name: str) -> str:
        pass
