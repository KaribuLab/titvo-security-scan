import os
import sys
import base64
import logging
from dotenv import load_dotenv
from anthropic import Anthropic
from github import Github

# Configurar el logger
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger("github_security_scan")

# Cargar variables de entorno desde el archivo .env
load_dotenv()

# Obtener las claves API desde el archivo .env
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
GITHUB_REPO_NAME = os.getenv("GITHUB_REPO_NAME")
GITHUB_COMMIT_SHA = os.getenv("GITHUB_COMMIT_SHA")
GITHUB_ASSIGNEE = os.getenv("GITHUB_ASSIGNEE")  # Usuario para asignar issues
TITVO_SCAN_TASK_ID = os.getenv("TITVO_SCAN_TASK_ID")  # ID del trabajo de escaneo

if not all(
    [
        ANTHROPIC_API_KEY,
        GITHUB_TOKEN,
        GITHUB_REPO_NAME,
        GITHUB_COMMIT_SHA,
        TITVO_SCAN_TASK_ID,
    ]
):
    logger.error("Faltan variables de entorno.")
    logger.error("Asegúrate de configurar las siguientes variables en el archivo .env:")
    logger.error("- ANTHROPIC_API_KEY")
    logger.error("- GITHUB_TOKEN")
    logger.error("- GITHUB_REPO_NAME (formato: usuario/repositorio)")
    logger.error("- GITHUB_COMMIT_SHA")
    logger.error("- GITHUB_ASSIGNEE")
    logger.error("- TITVO_SCAN_TASK_ID")
    sys.exit(1)

# Imprimir el ID del trabajo de escaneo después de la validación
logger.info("ID del trabajo de escaneo: %s", TITVO_SCAN_TASK_ID)

# Modelo a utilizar
MODELO = "claude-3-7-sonnet-latest"


def descargar_archivos_repositorio(github_instance):
    """Descarga los archivos del repositorio en el commit especificado."""
    try:
        # Obtener el repositorio
        repo = github_instance.get_repo(GITHUB_REPO_NAME)
        logger.info("Accediendo al repositorio: %s", GITHUB_REPO_NAME)

        # Obtener el commit específico
        commit = repo.get_commit(GITHUB_COMMIT_SHA)
        logger.info("Obteniendo archivos del commit: %s", GITHUB_COMMIT_SHA)

        # Crear directorio para los archivos si no existe
        os.makedirs("repo_files", exist_ok=True)

        # Descargar cada archivo del commit
        for file in commit.files:
            try:
                # Obtener el contenido del archivo
                content = repo.get_contents(file.filename, ref=GITHUB_COMMIT_SHA)

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

                logger.info("Archivo descargado: %s", file.filename)

            # pylint: disable=broad-exception-caught
            except Exception as e:
                # pylint: enable=broad-exception-caught
                logger.error("Error al descargar %s: %s", file.filename, e)

        return True

    # pylint: disable=broad-exception-caught
    except Exception as e:
        # pylint: enable=broad-exception-caught
        logger.error("Error al acceder al repositorio: %s", e)
        return False


def obtener_contenido_archivos():
    """Obtiene el contenido de todos los archivos descargados."""
    contenido_archivos = ""
    logger.info("Obteniendo contenido de los archivos descargados")

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
                contenido_archivos += (
                    f"\n\n**Archivo: {ruta_relativa}**\n```\n{contenido}\n```"
                )
                logger.debug(
                    "Contenido del archivo %s añadido al prompt", ruta_relativa
                )
            # pylint: disable=broad-exception-caught
            except Exception as e:
                # pylint: enable=broad-exception-caught
                logger.error("Error al leer el archivo %s: %s", ruta_relativa, e)
                contenido_archivos += (
                    f"\n\n**Archivo: {ruta_relativa}**\n```\n"
                    f"Error al leer el archivo: {e}\n```"
                )

    return contenido_archivos


def crear_issue_github(analisis, commit_sha, github_instance):
    """Crea un issue en GitHub con el análisis de vulnerabilidades."""
    try:
        logger.info("Creando issue en GitHub con el análisis de vulnerabilidades")

        # Obtener el repositorio
        repo = github_instance.get_repo(GITHUB_REPO_NAME)

        # Obtener el commit específico
        commit = repo.get_commit(commit_sha)

        # Crear el título del issue
        titulo = f"Análisis de seguridad del commit {commit_sha[:7]}"

        # Crear el cuerpo del issue
        cuerpo = (
            f"# Análisis de seguridad para el commit {commit_sha}\n\n"
            f"Commit realizado por: {commit.commit.author.name}\n\n"
            f"## Resultados del análisis\n\n{analisis}"
        )

        # Crear el issue
        issue = repo.create_issue(title=titulo, body=cuerpo)

        # Asignar el issue al usuario especificado en la variable de ambiente
        try:
            # Solo asignar si hay un usuario configurado
            if GITHUB_ASSIGNEE:
                logger.info(
                    "Asignando issue al usuario configurado: %s", GITHUB_ASSIGNEE
                )
                # Asignar el issue
                issue.add_to_assignees(GITHUB_ASSIGNEE)
                logger.info("Issue asignado a %s", GITHUB_ASSIGNEE)

        except Exception as e:
            logger.warning("Error al asignar el issue: %s", e)
            logger.warning("Tipo de error: %s", type(e).__name__)

        return issue.html_url

    except Exception as e:
        logger.error("Error al crear el issue en GitHub: %s", e)
        return None


# Prompt de sistema - Modifica esto según tus necesidades
SYSTEM_PROMPT = """
Eres Claude, un experto en seguridad informática y ciberseguridad.
Tu especialidad es el análisis de vulnerabilidades en código fuente, especialmente en código que no es capaz de detectarse en un análisis SAST.
Tu objetivo es analizar el código fuente de un repositorio y proporcionar un resumen de las vulnerabilidades encontradas.

FORMATO DE RESPUESTA:
1. SIEMPRE debes comenzar tu respuesta con uno de estos dos patrones:
   - "[COMMIT_RECHAZADO] - Este commit contiene vulnerabilidades de seguridad" (si encuentras vulnerabilidades de severidad media, alta o crítica)
   - "[COMMIT_APROBADO] - Este commit no contiene vulnerabilidades de seguridad significativas" (si no encuentras vulnerabilidades o solo encuentras de severidad baja)

2. Luego, proporciona un análisis detallado de las vulnerabilidades encontradas, organizadas por tipo y severidad.

3. Para cada vulnerabilidad, incluye:
   - Descripción del problema
   - Ubicación exacta (archivo y línea)
   - Impacto potencial
   - Recomendación para solucionarlo

Este formato es CRÍTICO para el procesamiento automatizado de tu respuesta.
"""


def es_commit_seguro(analisis):
    """Determina si el commit es seguro basado en el análisis de Claude."""
    # Buscar el patrón específico que indica rechazo
    patron_rechazo = "[COMMIT_RECHAZADO]"

    # Si el análisis contiene el patrón de rechazo, el commit no es seguro
    if patron_rechazo in analisis:
        return False

    # Si no se encontró el patrón de rechazo, el commit es seguro
    return True


def main():
    """Función principal para obtener una respuesta de Claude."""
    logger.info("Iniciando análisis de seguridad")

    # Inicializar el cliente de GitHub
    github_client = Github(GITHUB_TOKEN)

    # Descargar archivos del repositorio
    if not descargar_archivos_repositorio(github_client):
        logger.error("No se pudieron descargar los archivos del repositorio.")
        return

    # Obtener el contenido de los archivos
    contenido_archivos = obtener_contenido_archivos()

    # Inicializar el cliente de Anthropic
    client = Anthropic(api_key=ANTHROPIC_API_KEY)
    logger.info("Enviando código para análisis")

    try:
        user_prompt = f"""
        A continuación te proporciono el código fuente de un commit específico 
        del repositorio {GITHUB_REPO_NAME} (commit: {GITHUB_COMMIT_SHA}).
        
        El formato de presentación es el siguiente:
        - Cada archivo se presenta con su nombre en formato **Archivo: ruta/al/archivo**
        - Seguido por el contenido del archivo dentro de un bloque de código markdown
        
        Analiza el código y proporciona un resumen de las vulnerabilidades encontradas en formato markdown, organizadas por tipo de vulnerabilidad y severidad.
        
        Recuerda que debes comenzar tu respuesta con el patrón [COMMIT_RECHAZADO] o [COMMIT_APROBADO] según corresponda.
        
        Código fuente a analizar:{contenido_archivos}
        """

        # Enviar la solicitud a Claude
        respuesta = client.messages.create(
            model=MODELO,
            max_tokens=4000,
            temperature=0.7,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_prompt}],
        )

        # Obtener el análisis de Claude
        analisis = respuesta.content[0].text
        logger.info("Análisis de seguridad recibido de Claude")

        # Mostrar la respuesta
        logger.info("Respuesta de Claude:\n%s", analisis)

        # Crear un issue en GitHub con el análisis
        issue_url = crear_issue_github(analisis, GITHUB_COMMIT_SHA, github_client)
        if issue_url:
            logger.info("Se ha creado un issue con el análisis: %s", issue_url)

        # Verificar si el commit es seguro
        if not es_commit_seguro(analisis):
            logger.error(
                "¡COMMIT RECHAZADO! Se han detectado vulnerabilidades de seguridad."
            )
            logger.error(
                "Revisa el issue creado en GitHub para más detalles: %s", issue_url
            )
        else:
            logger.info(
                "COMMIT APROBADO. No se detectaron vulnerabilidades de seguridad significativas."
            )

    # pylint: disable=broad-exception-caught
    except Exception as e:
        # pylint: enable=broad-exception-caught
        logger.exception(e)
        sys.exit(1)


if __name__ == "__main__":
    main()
