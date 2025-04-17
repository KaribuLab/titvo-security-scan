import os
import base64
import logging
from github import Github

LOGGER = logging.getLogger(__name__)


def download_repository_files(
    github_instance: Github, github_repo_name: str, github_commit_sha: str
):
    """Descarga los archivos del repositorio en el commit especificado."""
    try:
        # Obtener el repositorio
        LOGGER.info("Accediendo al repositorio: %s", github_repo_name)
        repo = github_instance.get_repo(github_repo_name)

        # Obtener el commit específico
        LOGGER.info("Obteniendo archivos del commit: %s", github_commit_sha)
        commit = repo.get_commit(github_commit_sha)

        # Crear directorio para los archivos si no existe
        os.makedirs("repo_files", exist_ok=True)

        # Descargar cada archivo del commit
        for file in commit.files:
            try:
                # Obtener el contenido del archivo
                content = repo.get_contents(file.filename, ref=github_commit_sha)

                # Crear directorios necesarios
                os.makedirs(
                    os.path.dirname(f"repo_files/{file.filename}"), exist_ok=True
                )

                # Decodificar y guardar el contenido
                if isinstance(content.content, str):
                    file_content = base64.b64decode(content.content).decode("utf-8")
                else:
                    file_content = content.decoded_content.decode("utf-8")

                with open(f"repo_files/{file.filename}", "w", encoding="utf-8") as f:
                    f.write(file_content)

                LOGGER.info("Archivo descargado: %s", file.filename)

            except Exception as e:
                LOGGER.error("Error al descargar %s:", file.filename)
                LOGGER.exception(e)

        return True

    except Exception as e:
        LOGGER.error("Error al acceder al repositorio:")
        LOGGER.exception(e)
        return False


def create_issue(
    analysis, commit_sha, github_instance, github_repo_name, github_assignee
):
    """Crea un issue en GitHub con el análisis de vulnerabilidades."""
    try:
        LOGGER.info("Creando issue en GitHub con el análisis de vulnerabilidades")

        # Obtener el repositorio
        repo = github_instance.get_repo(github_repo_name)

        # Obtener el commit específico
        commit = repo.get_commit(commit_sha)

        # Crear el título del issue
        title = f"[BUG] Problema de seguridad en el commit {commit_sha[:7]}"

        # Crear el cuerpo del issue
        body = (
            f"# 🐛 Problema de seguridad detectado\n\n"
            f"**Commit:** {commit_sha}\n"
            f"**Autor:** {commit.commit.author.name}\n\n"
            f"## Resultados del análisis\n\n{analysis}"
        )

        # Crear el issue con etiquetas de seguridad
        issue = repo.create_issue(title=title, body=body, labels=["bug"])

        # Asignar el issue al usuario especificado en la variable de ambiente
        try:
            # Solo asignar si hay un usuario configurado
            if github_assignee:
                LOGGER.info(
                    "Asignando issue al usuario configurado: %s", github_assignee
                )
                # Asignar el issue
                issue.add_to_assignees(github_assignee)
                LOGGER.info("Issue asignado a %s", github_assignee)

        except Exception as e:
            LOGGER.warning("Error al asignar el issue:")
            LOGGER.exception(e)
            LOGGER.warning("Tipo de error: %s", type(e).__name__)

        return issue.html_url

    except Exception as e:
        LOGGER.error("Error al crear el issue en GitHub:")
        LOGGER.exception(e)
        return None

def is_commit_warning(analysis):
    """Determina si el commit es un warning basado en el análisis de Claude."""
    if "[COMMIT_CON_OBSERVACIONES]" in analysis:
        return False
    return True

def is_commit_safe(analysis):
    """Determina si el commit es seguro basado en el análisis de Claude."""
    # Si el análisis contiene el patrón de rechazo, el commit no es seguro
    if "[COMMIT_RECHAZADO]" in analysis:
        return False
    # Si no se encontró el patrón de rechazo, el commit es seguro
    return True
