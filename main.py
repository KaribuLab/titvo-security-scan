import os
import logging
import json
from dotenv import load_dotenv
from langchain.chat_models import init_chat_model

# Importar los módulos refactorizados
import github_handler
import bitbucket_handler
import cli_handler
import utils
import aws_utils

# Cargar variables de entorno desde el archivo .env
load_dotenv()

# Configurar el nivel de log desde variable de ambiente
log_level_name = os.getenv("LOG_LEVEL", "INFO")
log_level = getattr(logging, log_level_name.upper(), logging.INFO)

# Configurar el logger
logging.basicConfig(
    level=log_level,
    format="%(asctime)s - %(levelname)s - %(name)s:%(lineno)d - %(message)s",
    handlers=[logging.StreamHandler()],
)
LOGGER = logging.getLogger("github_security_scan")

# Obtener las claves API desde el archivo .env
TITVO_SCAN_TASK_ID = os.getenv("TITVO_SCAN_TASK_ID")  # ID del trabajo de escaneo


def main():
    """Función principal para obtener una respuesta de Claude."""
    LOGGER.info("Iniciando análisis de seguridad")

    # Validar variables de ambiente
    if not utils.validate_environment_variables(TITVO_SCAN_TASK_ID):
        utils.exit_with_error("Faltan variables de ambiente requeridas")

    # Imprimir el ID del trabajo de escaneo después de la validación
    LOGGER.info("ID del trabajo de escaneo: %s", TITVO_SCAN_TASK_ID)

    # Obtener el item de escaneo desde DynamoDB
    item_scan = aws_utils.get_scan_item(TITVO_SCAN_TASK_ID)
    if not item_scan:
        utils.exit_with_error(
            "No se pudo obtener la información del escaneo desde DynamoDB",
            TITVO_SCAN_TASK_ID,
        )

    # Actualizar el estado a IN_PROGRESS
    if not aws_utils.update_scan_status(TITVO_SCAN_TASK_ID, "IN_PROGRESS"):
        utils.exit_with_error(
            "No se pudo actualizar el estado del escaneo a IN_PROGRESS",
            TITVO_SCAN_TASK_ID,
        )
    hint = None
    if item_scan.get("repository_id") is not None:
        hint = aws_utils.get_hint_item(item_scan.get("repository_id"))

    # Obtener el system prompt desde Parameter Store
    base_prompt = aws_utils.get_base_prompt(utils.MODEL)
    if not base_prompt:
        utils.exit_with_error(
            "No se pudo obtener el base prompt desde Parameter Store. "
            "Este parámetro es obligatorio.",
            TITVO_SCAN_TASK_ID,
        )

    output_format = aws_utils.get_output_format(item_scan.get("source"))
    if not output_format:
        utils.exit_with_error(
            "No se pudo obtener el formato de salida desde Parameter Store. "
            "Este parámetro es obligatorio.",
            TITVO_SCAN_TASK_ID,
        )
    LOGGER.info("Formato de salida obtenido correctamente")

    system_prompt = f"{base_prompt}\n\n{output_format}"

    model = init_chat_model(
        utils.MODEL, model_provider="openai", api_key=aws_utils.get_openai_api_key()
    )

    LOGGER.info("Enviando código para análisis")

    try:
        if item_scan.get("source") == "github":
            process_github_scan(model, system_prompt, hint, item_scan)
        elif item_scan.get("source") == "bitbucket":
            process_bitbucket_scan(model, system_prompt, hint, item_scan)
        elif item_scan.get("source") == "cli":
            process_cli_scan(model, system_prompt, hint, item_scan)
        else:
            LOGGER.info("No se pudo obtener el source del escaneo")
            utils.exit_with_error(
                "No se pudo obtener el source del escaneo", TITVO_SCAN_TASK_ID
            )

    except Exception as e:
        LOGGER.exception(e)
        utils.exit_with_error(e, TITVO_SCAN_TASK_ID)


def process_github_scan(model, system_prompt, hint, item_scan):
    """Procesa un escaneo de GitHub."""
    # Inicializar el cliente de GitHub
    github_client = github_handler.Github(
        aws_utils.decrypt(item_scan.get("args").get("github_token"))
    )
    github_repo_name = item_scan.get("args").get("github_repo_name").replace('"', "")
    github_commit_sha = item_scan.get("args").get("github_commit_sha").replace('"', "")
    github_assignee = item_scan.get("args").get("github_assignee").replace('"', "")

    # Descargar archivos del repositorio
    if not github_handler.download_repository_files(
        github_client, github_repo_name, github_commit_sha
    ):
        utils.exit_with_error(
            "No se pudieron descargar los archivos del repositorio.",
            TITVO_SCAN_TASK_ID,
        )

    # Obtener el contenido de los archivos
    files_content = utils.get_files_content()

    # Preparar información del repositorio
    repo_info = {
        "source": "github",
        "repo_name": github_repo_name,
        "commit_sha": github_commit_sha,
        "assignee": github_assignee,
        "client": github_client,
    }

    # Generar el prompt
    user_prompt = utils.generate_security_analysis_prompt(
        repo_info, files_content, hint
    )

    if not user_prompt:
        utils.exit_with_error(
            "No se pudo generar el prompt para el análisis de seguridad",
            TITVO_SCAN_TASK_ID,
        )

    # Realizar el análisis
    is_safe, is_warning, analysis = utils.analyze_code(
        model,
        system_prompt,
        user_prompt,
        TITVO_SCAN_TASK_ID,
        item_scan.get("source"),
    )

    if not is_safe:
        # Crear un issue en GitHub solo si se detectan vulnerabilidades
        issue_url = github_handler.create_issue(
            analysis,
            github_commit_sha,
            github_client,
            github_repo_name,
            github_assignee,
        )
        if issue_url:
            LOGGER.info("Se ha creado un issue con el análisis: %s", issue_url)
            LOGGER.error(
                "Revisa el issue creado en GitHub para más detalles: %s",
                issue_url,
            )
            # Actualizar el estado con la URL del issue
            aws_utils.update_scan_status(
                TITVO_SCAN_TASK_ID,
                "FAILED",
                {
                    "issue_url": issue_url,
                },
            )
    else:
        result = {}
        if is_warning:
            LOGGER.info("Se ha creado un issue con el análisis: %s", issue_url)
            issue_url = github_handler.create_issue(
                analysis,
                github_commit_sha,
                github_client,
                github_repo_name,
                github_assignee,
            )
            result["issue_url"] = issue_url
        aws_utils.update_scan_status(
            TITVO_SCAN_TASK_ID,
            "COMPLETED",
            result,
        )


def process_bitbucket_scan(model, system_prompt, hint, item_scan):
    """Procesa un escaneo de Bitbucket."""
    try:
        # Obtener parámetros de Bitbucket
        bitbucket_workspace = (
            item_scan.get("args").get("bitbucket_workspace").replace('"', "")
        )
        bitbucket_repo_slug = (
            item_scan.get("args").get("bitbucket_repo_slug").replace('"', "")
        )
        bitbucket_project_key = (
            item_scan.get("args").get("bitbucket_project_key").replace('"', "")
        )
        bitbucket_commit = (
            item_scan.get("args").get("bitbucket_commit").replace('"', "")
        )

        access_token = bitbucket_handler.get_access_token(
            aws_utils.get_secret_manager_parameter
        )
        if not access_token:
            utils.exit_with_error(
                "No se pudo obtener el token de Bitbucket",
                TITVO_SCAN_TASK_ID,
            )

        # Descargar archivos del repositorio
        if not bitbucket_handler.download_repository_files(
            access_token,
            bitbucket_workspace,
            bitbucket_repo_slug,
            bitbucket_commit,
        ):
            utils.exit_with_error(
                "No se pudieron descargar los archivos del repositorio de Bitbucket.",
                TITVO_SCAN_TASK_ID,
            )

        # Obtener el contenido de los archivos
        files_content = utils.get_files_content()

        # Preparar información del repositorio
        repo_info = {
            "source": "bitbucket",
            "workspace": bitbucket_workspace,
            "repo_slug": bitbucket_repo_slug,
            "project_key": bitbucket_project_key,
            "commit_sha": bitbucket_commit,
        }

        # Generar el prompt
        user_prompt = utils.generate_security_analysis_prompt(
            repo_info, files_content, hint
        )

        if not user_prompt:
            utils.exit_with_error(
                "No se pudo generar el prompt para el análisis de seguridad",
                TITVO_SCAN_TASK_ID,
            )

        # Realizar el análisis
        is_safe, is_warning, analysis = utils.analyze_code(
            model,
            system_prompt,
            user_prompt,
            TITVO_SCAN_TASK_ID,
            item_scan.get("source"),
        )

        analysis_json = json.loads(analysis)

        if not is_safe:
            report_url = bitbucket_handler.create_code_insights_report(
                access_token,
                bitbucket_workspace,
                bitbucket_repo_slug,
                bitbucket_commit,
                is_safe,
                analysis_json,
                item_scan.get("source"),
                TITVO_SCAN_TASK_ID,
                utils.generate_and_upload_html_report,
            )
            if report_url is not None:
                LOGGER.info(
                    "Se ha creado un reporte de código en Bitbucket: %s", report_url
                )
                LOGGER.error(
                    "Revisa el reporte de código en Bitbucket para más detalles: %s",
                    report_url,
                )
                # Actualizar el estado a FAILED
                aws_utils.update_scan_status(
                    TITVO_SCAN_TASK_ID,
                    "FAILED",
                    {
                        "report_url": report_url,
                    },
                )
            else:
                utils.exit_with_error(
                    "No se pudo crear el reporte de código en Bitbucket",
                    TITVO_SCAN_TASK_ID,
                )
        else:
            result = {}
            if is_warning:
                report_url = bitbucket_handler.create_code_insights_report(
                    access_token,
                    bitbucket_workspace,
                    bitbucket_repo_slug,
                    bitbucket_commit,
                    is_safe,
                    analysis_json,
                    item_scan.get("source"),
                    TITVO_SCAN_TASK_ID,
                    utils.generate_and_upload_html_report,
                )
                result["report_url"] = report_url
            aws_utils.update_scan_status(
                TITVO_SCAN_TASK_ID,
                "COMPLETED",
                result,
            )
    except Exception as e:
        LOGGER.exception(e)
        utils.exit_with_error(e, TITVO_SCAN_TASK_ID)


def process_cli_scan(model, system_prompt, hint, item_scan):
    """Procesa un escaneo de CLI."""
    try:
        batch_id = item_scan.get("args").get("batch_id", "").replace('"', "")
        if batch_id == "":
            utils.exit_with_error(
                "No se pudo obtener el batch_id",
                TITVO_SCAN_TASK_ID,
            )

        # Obtener nombre del bucket para descargar archivos
        bucket_name = cli_handler.get_files_bucket_name(aws_utils.get_ssm_parameter)

        # Descargar archivos del repositorio
        for file in cli_handler.get_files_by_batch_id(
            batch_id, aws_utils.get_ssm_parameter
        ):
            if not cli_handler.file_download(
                file.get("file_key"), bucket_name, aws_utils.s3
            ):
                utils.exit_with_error(
                    "No se pudieron descargar los archivos del repositorio de CLI",
                    TITVO_SCAN_TASK_ID,
                )

        # Obtener el contenido de los archivos
        file_content = utils.get_files_content()

        LOGGER.debug("Contenido del archivo: %s", file_content)

        repo_info = {
            "source": "cli",
        }

        # Generar el prompt
        user_prompt = utils.generate_security_analysis_prompt(
            repo_info, file_content, hint
        )

        if not user_prompt:
            utils.exit_with_error(
                "No se pudo generar el prompt para el análisis de seguridad",
                TITVO_SCAN_TASK_ID,
            )

        # Realizar el análisis
        is_safe, is_warning, analysis = utils.analyze_code(
            model,
            system_prompt,
            user_prompt,
            TITVO_SCAN_TASK_ID,
            item_scan.get("source"),
        )

        analysis_json = json.loads(analysis)

        LOGGER.info("Análisis completado")

        if not is_safe:
            report_url = utils.generate_and_upload_html_report(
                analysis_json, TITVO_SCAN_TASK_ID, item_scan.get("source")
            )
            if report_url is not None:
                LOGGER.info("Reporte HTML creado y subido a S3: %s", report_url)
                LOGGER.error(
                    "Revisa el reporte HTML en S3 para más detalles: %s",
                    report_url,
                )
                aws_utils.update_scan_status(
                    TITVO_SCAN_TASK_ID,
                    "FAILED",
                    {
                        "report_url": report_url,
                    },
                )
            else:
                utils.exit_with_error(
                    "No se pudo crear el reporte de código en CLI",
                    TITVO_SCAN_TASK_ID,
                )
        else:
            result = {}
            if is_warning:
                report_url = utils.generate_and_upload_html_report(
                    analysis_json, TITVO_SCAN_TASK_ID, item_scan.get("source")
                )
                result["report_url"] = report_url
            aws_utils.update_scan_status(
                TITVO_SCAN_TASK_ID,
                "COMPLETED",
                result,
            )
    except Exception as e:
        LOGGER.exception(e)
        utils.exit_with_error(e, TITVO_SCAN_TASK_ID)


if __name__ == "__main__":
    main()
