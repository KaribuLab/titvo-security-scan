import os
import uuid
import json
import logging
import requests

LOGGER = logging.getLogger(__name__)

ACCESS_TOKEN_URL = "https://bitbucket.org/site/oauth2/access_token"
BITBUCKET_API_URL = "https://api.bitbucket.org/2.0"


def get_access_token(get_secret_manager_parameter):
    """Obtiene un token de acceso para Bitbucket."""
    client_credentials = get_secret_manager_parameter(
        f"/tvo/security-scan/{os.getenv('AWS_STAGE','prod')}/bitbucket_client_credentials"
    )
    if client_credentials is not None or client_credentials != "":
        credentials = json.loads(client_credentials)
        client_id = credentials.get("key")
        client_secret = credentials.get("secret")
        response = requests.post(
            ACCESS_TOKEN_URL,
            data={
                "client_id": client_id,
                "client_secret": client_secret,
                "grant_type": "client_credentials",
            },
            timeout=30,
        )
        if response.status_code == 200:
            return response.json().get("access_token")
        else:
            LOGGER.error("Error al obtener el token de Bitbucket: %s", response.json())
            return None
    return None


def download_file(headers, workspace, repo, file_path, commit):
    """Descarga un archivo específico del commit."""
    content_url = (
        f"{BITBUCKET_API_URL}/repositories/{workspace}/{repo}/src/{commit}/{file_path}"
    )
    response = requests.get(content_url, headers=headers, timeout=30)

    if response.status_code == 200:
        # Crear directorios si no existen
        full_path = os.path.join("repo_files", file_path)
        dirname = os.path.dirname(full_path)
        if dirname != "":
            os.makedirs(dirname, exist_ok=True)

        # Guardar el contenido directamente
        with open(full_path, "w", encoding="utf-8") as f:
            f.write(response.text)
        LOGGER.info("✓ Descargado: %s", full_path)
        return True
    return False


def download_repository_files(
    access_token: str,
    bitbucket_workspace: str,
    bitbucket_repo_slug: str,
    bitbucket_commit: str,
):
    """Descarga los archivos del repositorio de Bitbucket en el commit especificado.

    Args:
        bitbucket_workspace (str): El workspace de Bitbucket
        bitbucket_repo_slug (str): El slug del repositorio
        bitbucket_project_key (str): La clave del proyecto
        bitbucket_commit (str): El SHA del commit

    Returns:
        bool: True si la descarga fue exitosa, False en caso contrario
    """
    if access_token is None:
        LOGGER.error("No se pudo obtener el token de Bitbucket")
        return False

    try:
        LOGGER.info(
            "Accediendo al repositorio de Bitbucket: %s/%s",
            bitbucket_workspace,
            bitbucket_repo_slug,
        )
        LOGGER.info("Commit: %s", bitbucket_commit)

        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
        }

        # Obtener información del commit específico usando la API REST
        commit_url = (
            f"{BITBUCKET_API_URL}/repositories/{bitbucket_workspace}/"
            f"{bitbucket_repo_slug}/commit/{bitbucket_commit}"
        )
        commit_response = requests.get(commit_url, headers=headers, timeout=30)

        if commit_response.status_code == 200:
            commit_info = commit_response.json()
            LOGGER.info("Información del commit %s:", bitbucket_commit)
            LOGGER.info("Hash: %s", commit_info["hash"])
            LOGGER.info("Fecha: %s", commit_info["date"])
            LOGGER.info("Mensaje: %s", commit_info["message"])
            LOGGER.info("Autor: %s", commit_info["author"]["raw"])

            # Obtener la lista de archivos modificados
            diff_url = (
                f"{BITBUCKET_API_URL}/repositories/{bitbucket_workspace}/"
                f"{bitbucket_repo_slug}/diff/{bitbucket_commit}"
            )
            diff_response = requests.get(diff_url, headers=headers, timeout=30)

            if diff_response.status_code == 200:
                diff_content = diff_response.text
                # Extraer los nombres de archivos del diff
                files = set()
                for line in diff_content.split("\n"):
                    if line.startswith("diff --git"):
                        # El formato es: diff --git a/path/to/file b/path/to/file
                        file_path = line.split(" b/")[1]
                        files.add(file_path)

                LOGGER.info("\nArchivos modificados:")
                for file in sorted(files):
                    LOGGER.info("- %s", file)

                LOGGER.info("\nDescargando archivos...")
                successful_downloads = 0
                for file in sorted(files):
                    if download_file(
                        headers,
                        bitbucket_workspace,
                        bitbucket_repo_slug,
                        file,
                        bitbucket_commit,
                    ):
                        successful_downloads += 1

                LOGGER.info(
                    "Resumen de descargas: %s/%s archivos descargados exitosamente",
                    successful_downloads,
                    len(files),
                )
            else:
                LOGGER.error(
                    "Error al obtener los archivos modificados: %s - %s",
                    diff_response.status_code,
                    diff_response.text,
                )
        else:
            LOGGER.error(
                "No se encontró el commit con hash %s",
                bitbucket_commit,
            )
            LOGGER.error(
                "Error: %s - %s",
                commit_response.status_code,
                commit_response.text,
            )

        return True

    except Exception as e:
        LOGGER.error("Error al acceder al repositorio de Bitbucket:")
        LOGGER.exception(e)
        return False


def analysis_to_annotation(analysis_annotations, report_id):
    """Convierte el análisis a anotaciones para Bitbucket."""
    annotations = []
    for item in analysis_annotations:
        current_annotation = {}
        current_annotation["external_id"] = f"{report_id}-annotation-{uuid.uuid4()}"
        current_annotation["annotation_type"] = "VULNERABILITY"
        current_annotation["title"] = item.get("title")
        current_annotation["description"] = item.get("description")
        current_annotation["severity"] = item.get("severity")
        current_annotation["path"] = item.get("path")
        current_annotation["line"] = item.get("line")
        current_annotation["summary"] = item.get("summary")
        annotations.append(current_annotation)

    return annotations


def create_code_insights_report(
    access_token,
    workspace,
    repo,
    commit,
    is_safe,
    analysis,
    source,
    titvo_scan_task_id,
    generate_and_upload_html_report,
) -> str:
    """Crea un reporte de código en Bitbucket."""
    try:
        report_id = f"titvo-security-scan-{uuid.uuid4()}"
        create_report_url = (
            f"{BITBUCKET_API_URL}/repositories/{workspace}/{repo}/commit/{commit}/reports/"
            f"{report_id}"
        )
        create_annotation_url = (
            f"{BITBUCKET_API_URL}/repositories/{workspace}/{repo}/commit/{commit}/reports/"
            f"{report_id}/annotations"
        )
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        }

        # Parsear el análisis JSON
        json_analysis = json.loads(analysis)

        # Añadir información adicional para la plantilla
        json_analysis["workspace"] = workspace
        json_analysis["repo_slug"] = repo
        json_analysis["commit_sha"] = commit

        # Generar y subir el reporte HTML, pasando el source
        report_url = generate_and_upload_html_report(
            json_analysis, titvo_scan_task_id, source
        )
        if not report_url:
            LOGGER.error("No se pudo generar o subir el reporte HTML")
            return None

        # Obtener las anotaciones del análisis
        analysis_annotations = json_analysis.get("annotations", [])

        # Crear el payload del reporte para Bitbucket
        payload = {
            "title": "Titvo Security Scan",
            "details": "Security scan report",
            "report_type": "SECURITY",
            "reporter": "titvo-security-scan",
            "result": "FAILED" if not is_safe else "SUCCESS",
            "data": [
                {
                    "title": "Safe to merge?",
                    "type": "BOOLEAN",
                    "value": is_safe,
                },
                {
                    "title": "Number of issues",
                    "type": "NUMBER",
                    "value": json_analysis.get("number_of_issues", 0),
                },
                {
                    "title": "Report",
                    "type": "LINK",
                    "value": {"text": "See full report", "href": report_url},
                },
            ],
        }

        # Crear el reporte en Bitbucket
        response = requests.put(
            create_report_url, headers=headers, json=payload, timeout=30
        )

        if response.status_code != 200:
            if response.json().get("key", "") == "report-service.report.max-reports":
                LOGGER.info("El reporte de código en Bitbucket está lleno")
                return ""
            LOGGER.error(
                "Error al crear el reporte de código en Bitbucket: %s", response.json()
            )
            return None

        # Crear las anotaciones si hay alguna
        if analysis_annotations:
            annotation_payload = analysis_to_annotation(analysis_annotations, report_id)
            annotation_response = requests.post(
                create_annotation_url,
                headers=headers,
                json=annotation_payload,
                timeout=30,
            )

            if annotation_response.status_code != 200:
                LOGGER.error(
                    "Error al crear las anotaciones: %s - %s",
                    annotation_response.status_code,
                    annotation_response.text,
                )

        return report_url
    except Exception as e:
        LOGGER.error("Error al crear el reporte de código en Bitbucket:")
        LOGGER.exception(e)
        return None


def is_commit_safe(analysis):
    """Determina si el commit es seguro basado en el análisis de Claude."""
    # Si el análisis contiene el patrón de rechazo, el commit no es seguro
    if "CRITICAL" in analysis or "HIGH" in analysis:
        return False
    # Si no se encontró el patrón de rechazo, el commit es seguro
    return True
