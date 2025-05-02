from dataclasses import dataclass
from titvo.core.ports.configuration_service import ConfigurationService
from titvo.core.ports.storage_service import StorageService
from titvo.infraestructure.outputs.outputs_factory import OutputsServiceFactoryImpl


@dataclass
class OutputsDependencies:
    outputs_service_factory: OutputsServiceFactoryImpl


def get_dependencies(
    configuration_service: ConfigurationService,
    storage_service: StorageService,
    template_path: str,
) -> OutputsDependencies:
    return OutputsDependencies(
        outputs_service_factory=OutputsServiceFactoryImpl(
            configuration_service, storage_service, template_path
        ),
    )
