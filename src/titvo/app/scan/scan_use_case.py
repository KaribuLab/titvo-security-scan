import os
from typing import List
from titvo.app.task.task_use_case import (
    GetTaskUseCase,
    MarkTaskInProgressUseCase,
    MarkTaskCompletedUseCase,
    MarkTaskFailedUseCase,
    MarkTaskErrorUseCase,
)
from titvo.app.hint.hint_use_case import GetHintUseCase
from titvo.app.scan.scan_entities import Scan, ScanStatus
from titvo.core.ports.ai_service import AiService
from titvo.core.ports.configuration_service import ConfigurationService
from titvo.infraestructure.file_fetchers.file_fetcher_factory import (
    FileFetcherServiceFactory,
)
from titvo.core.ports.output_service import OutputServiceFactory
from titvo.app.scan.scan_entities import Prompt


class RunScanUseCase:
    def __init__(
        self,
        get_task_use_case: GetTaskUseCase,
        mark_task_in_progress_use_case: MarkTaskInProgressUseCase,
        mark_task_completed_use_case: MarkTaskCompletedUseCase,
        mark_task_failed_use_case: MarkTaskFailedUseCase,
        mark_task_error_use_case: MarkTaskErrorUseCase,
        ai_service: AiService,
        configuration_service: ConfigurationService,
        hint_use_case: GetHintUseCase,
        file_fetcher_service_factory: FileFetcherServiceFactory,
        output_service_factory: OutputServiceFactory,
        repo_files_path: str,
    ):
        self.get_task_use_case = get_task_use_case
        self.mark_task_in_progress_use_case = mark_task_in_progress_use_case
        self.mark_task_completed_use_case = mark_task_completed_use_case
        self.mark_task_failed_use_case = mark_task_failed_use_case
        self.mark_task_error_use_case = mark_task_error_use_case
        self.ai_service = ai_service
        self.configuration_service = configuration_service
        self.hint_use_case = hint_use_case
        self.repo_files_path = repo_files_path
        self.file_fetcher_service_factory = file_fetcher_service_factory
        self.output_service_factory = output_service_factory

    def execute(self, scan: Scan) -> None:
        task = self.get_task_use_case.execute(scan.id)
        self.mark_task_in_progress_use_case.execute(task.id)
        system_prompt = self.configuration_service.get_value("scan_system_prompt")
        hint = self.hint_use_case.execute(task.hint_id)
        file_fetcher_service = (
            self.file_fetcher_service_factory.get_file_fetcher_service(task.source)
        )
        files: List[str] = file_fetcher_service.fetch_files()
        files_code = ""
        for file in files:
            relative_path = os.path.relpath(file, self.repo_files_path)
            with open(file, "r", encoding="utf-8") as f:
                file_content = f.read()

            files_code += f"\n\n**Archivo: {relative_path}**\n```\n{file_content}\n```"
        user_prompt = ""
        if hint is not None:
            user_prompt += f"""
Titvo soy el jefe de seguridad. A continuación comenzaré a darte una lista de sugerencias para que las uses en tu análisis:
==================================
{hint.hint}
==================================
Fin de las sugerencias.
"""

        user_prompt += f"""
A continuación te voy a dar una lista de archivos que vas a analizar:
==================================
{files_code}
==================================
Fin de la lista de archivos.
"""
        prompt = Prompt(system_prompt, user_prompt)
        ai_result = self.ai_service.execute(prompt)
        output_service = self.output_service_factory.get_output_service(task.source)
        output_result = output_service.execute(ai_result)
        if ai_result.status == ScanStatus.ERROR:
            self.mark_task_error_use_case.execute(task.id)
        else:
            self.mark_task_failed_use_case.execute(task.id, output_result, len(files))
