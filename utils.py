import os
import sys
import logging
from datetime import datetime
from jinja2 import Environment, FileSystemLoader
from github_handler import is_commit_safe as github_is_safe
from bitbucket_handler import is_commit_safe as bitbucket_is_safe
from cli_handler import is_commit_safe as cli_is_safe
# Importar funciones de AWS desde el nuevo módulo
from aws_utils import (
    update_scan_status,
    upload_html_to_s3,
)

LOGGER = logging.getLogger(__name__)
MODEL = "claude-3-7-sonnet-latest"


def validate_environment_variables(scan_task_id):
    """Valida que todas las variables de ambiente requeridas estén definidas."""
    if not scan_task_id:
        LOGGER.error("Faltan variables de entorno.")
        LOGGER.error(
            "Asegúrate de configurar las siguientes variables en el archivo .env:"
        )
        LOGGER.error("- TITVO_SCAN_TASK_ID")
        return False
    return True


def get_files_content():
    """Obtiene el contenido de todos los archivos descargados."""
    files_content = ""
    LOGGER.info("Obteniendo contenido de los archivos descargados")

    # Recorrer el directorio repo_files
    for root, _, files in os.walk("repo_files"):
        for file in files:
            # Construir la ruta completa del archivo
            ruta_archivo = os.path.join(root, file)

            # Obtener la ruta relativa para mostrarla en el prompt
            ruta_relativa = os.path.relpath(ruta_archivo, "repo_files")

            try:
                # Leer el contenido del archivo
                with open(ruta_archivo, "r", encoding="utf-8") as f:
                    contenido = f.read()

                # Añadir el nombre del archivo antes del bloque de código
                files_content += (
                    f"\n\n**Archivo: {ruta_relativa}**\n```\n{contenido}\n```"
                )
                LOGGER.debug(
                    "Contenido del archivo %s añadido al prompt", ruta_relativa
                )
            except Exception as e:
                LOGGER.error("Error al leer el archivo %s:", ruta_relativa)
                LOGGER.exception(e)
                files_content += (
                    f"\n\n**Archivo: {ruta_relativa}**\n```\n"
                    f"Error al leer el archivo: {str(e)}\n```"
                )

    return files_content


def generate_security_analysis_prompt(repo_info: dict, files_content: str) -> str:
    """Genera el prompt para el análisis de seguridad.

    Args:
        repo_info (dict): Diccionario con la información del repositorio
        files_content (str): Contenido de los archivos a analizar

    Returns:
        str: El prompt generado
    """
    repo_identifier = ""
    if repo_info.get("source") == "github":
        repo_identifier = repo_info.get("repo_name")
        return f"""
    A continuación te proporciono el código fuente de un commit específico 
    del repositorio {repo_identifier} (commit: {repo_info.get('commit_sha')}).
    Código fuente a analizar:{files_content}
    """
    elif repo_info.get("source") == "bitbucket":
        repo_identifier = f"{repo_info.get('workspace')}/{repo_info.get('repo_slug')}"
        return f"""
    A continuación te proporciono el código fuente de un commit específico 
    del repositorio {repo_identifier} (commit: {repo_info.get('commit_sha')}).
    Código fuente a analizar:{files_content}
    """
    elif repo_info.get("source") == "cli":
        repo_identifier = None
        return f"""
    A continuación te proporciono el código fuente de un commit específico.
    Código fuente a analizar:{files_content}
    """
    else:
        LOGGER.error("Fuente de repositorio no válida: %s", repo_info.get("source"))
        return None


def analyze_code(
    client, system_prompt: str, user_prompt: str, scan_id: str, source: str
) -> tuple[bool, str]:
    """Realiza el análisis de seguridad del código.

    Args:
        client: Cliente de Claude
        system_prompt (str): Prompt del sistema
        user_prompt (str): Prompt del usuario
        scan_id (str): ID del escaneo
        source (str): Fuente del análisis (github, bitbucket, cli)

    Returns:
        tuple[bool, str]: Una tupla con (True si el commit es seguro, el análisis de seguridad)
    """
    try:
        LOGGER.info("System prompt: %s", system_prompt)
        LOGGER.info("User prompt: %s", user_prompt)
        # Enviar la solicitud a Claude
        respuesta = client.messages.create(
            model=MODEL,
            temperature=0.7,
            max_tokens=4000,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
        )

        # Obtener el análisis de Claude
        analysis = respuesta.content[0].text
        LOGGER.info("Análisis de seguridad recibido")

        # Mostrar la respuesta
        LOGGER.debug("Respuesta :\n%s", analysis)

        # Importar dinámicamente el módulo correcto basado en la fuente
        if source == "github":
            is_safe = github_is_safe(analysis)
        elif source == "bitbucket":
            is_safe = bitbucket_is_safe(analysis)
        elif source == "cli":
            is_safe = cli_is_safe(analysis)
        else:
            LOGGER.error("Fuente no válida: %s", source)
            return False, analysis

        if not is_safe:
            LOGGER.error(
                "¡COMMIT RECHAZADO! Se han detectado vulnerabilidades de seguridad."
            )
            return False, analysis
        else:
            LOGGER.info(
                "COMMIT APROBADO. No se detectaron vulnerabilidades "
                "de seguridad significativas."
            )
            # Actualizar el estado a COMPLETED
            update_scan_status(scan_id, "COMPLETED")
            return True, analysis

    except Exception as e:
        LOGGER.exception(e)
        exit_with_error(e, scan_id)
        return False, ""


def exit_with_error(message, scan_id=None):
    """Actualiza el estado a ERROR en DynamoDB y termina el script con código 1.
    
    Args:
        message: Puede ser un string o una excepción
        scan_id: ID del escaneo para actualizar su estado
    """
    if isinstance(message, Exception):
        LOGGER.error("Error durante la ejecución:")
        LOGGER.exception(message)
    else:
        LOGGER.error(message)
        
    if scan_id:
        update_scan_status(scan_id, "ERROR")
    sys.exit(1)


def create_issue_html(json_analysis):
    """Genera el HTML del análisis usando una plantilla Jinja2."""
    try:
        # Configurar el entorno de Jinja2
        env = Environment(loader=FileSystemLoader("templates"))
        template = env.get_template("report_template.html")

        # Preparar los datos para la plantilla
        issues = json_analysis.get("annotations", [])
        total_issues = len(issues)

        # Contar issues por severidad
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        for issue in issues:
            severity = issue.get("severity", "").lower()
            if severity in severity_counts:
                severity_counts[severity] += 1

        # Renderizar la plantilla
        html_content = template.render(
            workspace=json_analysis.get("workspace", ""),
            repo_slug=json_analysis.get("repo_slug", ""),
            commit_sha=json_analysis.get("commit_sha", ""),
            scan_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            total_issues=total_issues,
            recommendation=json_analysis.get("recommendation", ""),
            critical_issues=severity_counts["critical"],
            high_issues=severity_counts["high"],
            medium_issues=severity_counts["medium"],
            low_issues=severity_counts["low"],
            issues=issues,
        )

        return html_content
    except Exception as e:
        LOGGER.error("Error al generar el HTML del reporte:")
        LOGGER.exception(e)
        error_html = (
            "<html><body>"
            "<h1>Error al generar el reporte</h1>"
            "<p>Ha ocurrido un error al generar el reporte HTML.</p>"
            "</body></html>"
        )
        return error_html


def generate_and_upload_html_report(json_analysis, scan_id, source):
    """Genera el reporte HTML basado en el análisis y lo sube a S3.

    Args:
        json_analysis (dict): Análisis de seguridad en formato JSON
        scan_id (str): ID del escaneo
        source (str): Fuente del análisis (github, bitbucket, cli)

    Returns:
        str: URL del reporte subido a S3, o None en caso de error
    """
    try:
        # Generar el HTML usando la plantilla
        html_analysis = create_issue_html(json_analysis)

        # Subir el HTML generado a S3
        report_url = upload_html_to_s3(html_analysis, scan_id, source)

        if report_url:
            LOGGER.info("Reporte HTML creado y subido a S3: %s", report_url)
            return report_url
        else:
            LOGGER.error("No se pudo subir el reporte HTML a S3")
            return None

    except Exception as e:
        LOGGER.error("Error al generar y subir el reporte HTML:")
        LOGGER.exception(e)
        return None
